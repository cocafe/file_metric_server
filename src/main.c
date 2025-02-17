#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>

#include <libjj/list.h>
#include <libjj/logging.h>
#include <libjj/jkey.h>
#include <libjj/opts.h>
#include <libjj/utils.h>

#include <libpromsrv/promsrv.h>

#include "tinyexpr.h"

int g_should_exit = 0;

static char listen_addr[256] = "0.0.0.0";
static uint32_t listen_port = 7799;
static char config_json[PATH_MAX] = "config.json";

lopt_strbuf_simple(config_json, "Path of config file");
lopt_strbuf_simple(listen_addr, "Listen address for metric server");
lopt_uint_simple(listen_port, "Listen port for metric server");

static jbuf_t jkey_root;

#define METRIC_LABEL_MAX                (5)

struct metric_label {
        struct list_head node;
        prom_label l;
};

struct metric {
        struct list_head node;
        struct list_head labels;
        prom_metric_def def;
        char path[PATH_MAX];
        char *expr;
        double val;
        uint8_t disabled;
};

struct metric_set {
        struct list_head node;
        struct list_head metrics;
        prom_metric_def def;
        uint8_t disabled;
};

static LIST_HEAD(metric_list);
static LIST_HEAD(metric_set_list);
static prom_metric_set metric_set;
static prom_server prom_srv;

int is_gonna_exit(void)
{
        return g_should_exit;
}

static int config_root_key_create(jbuf_t *b)
{
        void *root;
        int err;

        if ((err = jbuf_init(b, JBUF_INIT_ALLOC_KEYS))) {
                return err;
        }

        root = jbuf_obj_open(b, NULL);

        {
                void *arr_metrics = jbuf_list_arr_open(b, "metrics");
                jbuf_list_arr_setup(b,
                                    arr_metrics,
                                    &metric_list,
                                    sizeof(struct metric),
                                    offsetof(struct metric, node),
                                    0, 0);

                {
                        void *obj_metric = jbuf_offset_obj_open(b, NULL, 0);

                        jbuf_offset_add(b, strptr, "name", offsetof(struct metric, def.name));
                        jbuf_offset_add(b, strptr, "help", offsetof(struct metric, def.help));
                        jbuf_offset_add(b, strptr, "type", offsetof(struct metric, def.type));
                        jbuf_offset_add(b, strptr, "expr", offsetof(struct metric, expr));
                        jbuf_offset_strbuf_add(b, "path", offsetof(struct metric, path), sizeof(((struct metric *)(0))->path));

                        jbuf_obj_close(b, obj_metric);
                }

                jbuf_arr_close(b, arr_metrics);
        }

        {
                void *arr_metric_sets = jbuf_list_arr_open(b, "metric_sets");
                jbuf_list_arr_setup(b,
                                    arr_metric_sets,
                                    &metric_set_list,
                                    sizeof(struct metric_set),
                                    offsetof(struct metric_set, node),
                                    0, 0);

                {
                        void *obj_metric_set = jbuf_offset_obj_open(b, NULL, 0);

                        jbuf_offset_add(b, strptr, "name", offsetof(struct metric_set, def.name));
                        jbuf_offset_add(b, strptr, "help", offsetof(struct metric_set, def.help));
                        jbuf_offset_add(b, strptr, "type", offsetof(struct metric_set, def.type));

                        {
                                void *arr_metrics = jbuf_list_arr_open(b, "metrics");

                                jbuf_offset_list_arr_setup(b,
                                                           arr_metrics,
                                                           offsetof(struct metric_set, metrics),
                                                           sizeof(struct metric),
                                                           offsetof(struct metric, node),
                                                           0, 0);

                                {
                                        void *obj_metric = jbuf_offset_obj_open(b, NULL, 0);

                                        jbuf_offset_add(b, strptr, "expr", offsetof(struct metric, expr));
                                        jbuf_offset_strbuf_add(b, "path", offsetof(struct metric, path), sizeof(((struct metric *)(0))->path));

                                        {
                                                void *arr_labels = jbuf_list_arr_open(b, "labels");

                                                jbuf_offset_list_arr_setup(b,
                                                                           arr_labels,
                                                                           offsetof(struct metric, labels),
                                                                           sizeof(struct metric_label),
                                                                           offsetof(struct metric_label, node),
                                                                           0, 0);

                                                {
                                                        void *obj_label = jbuf_offset_obj_open(b, NULL, 0);

                                                        jbuf_offset_add(b, strptr, "key", offsetof(struct metric_label, l.key));
                                                        jbuf_offset_add(b, strptr, "val", offsetof(struct metric_label, l.value));

                                                        jbuf_obj_close(b, obj_label);
                                                }

                                                jbuf_arr_close(b, arr_labels);
                                        }

                                        jbuf_obj_close(b, obj_metric);
                                }

                                jbuf_arr_close(b, arr_metrics);
                        }

                        jbuf_obj_close(b, obj_metric_set);
                }

                jbuf_arr_close(b, arr_metric_sets);
        }

        jbuf_obj_close(b, root);

        return 0;
}

static int metric_def_validate(prom_metric_def *d)
{
        if (is_strptr_not_set(d->name)) {
                pr_err("metric has not set name\n");
                return -EINVAL;
        }

        if (is_strptr_not_set(d->type)) {
                pr_err("metric \"%s\" has empty type\n", d->name);
                return -EINVAL;
        }

        if (!is_str_equal((char *)d->type, "counter", 0) && !is_str_equal((char *)d->type, "gauge", 0)) {
                pr_err("metric \"%s\" has invalid type \"%s\"\n", d->name, d->type);
                return -EINVAL;
        }

        return 0;
}

static int metric_config_validate(struct metric *m)
{
        int err;

        if ((err = metric_def_validate(&m->def)))
                return err;

        if (is_strptr_not_set(m->path)) {
                pr_err("metric \"%s\" has empty path\n", m->def.name);
                return -EINVAL;
        }

        return 0;
}

static int metric_list_validate(void)
{
        struct metric *p;

        list_for_each_entry(p, &metric_list, node) {
                if (metric_config_validate(p))
                        p->disabled = 1;
        }

        return 0;
}

static int metric_set_element_validate(struct metric *m, char *name)
{
        if (is_strptr_not_set(m->path)) {
                pr_err("metric \"%s\" has empty path\n", name);
                return -EINVAL;
        }

        {
                struct metric_label *p, *n;

                if (m->labels.next == NULL && m->labels.prev == NULL) {
                        INIT_LIST_HEAD(&m->labels);
                        return 0;
                }

                list_for_each_entry_safe(p, n, &m->labels, node) {
                        if (is_strptr_not_set(p->l.key) || is_strptr_not_set(p->l.value)) {
                                pr_err("metric \"%s\" delete invalid empty label for path \"%s\"\n", name, m->path);
                                list_del(&p->node);
                        }
                }

                if (list_empty(&m->labels)) {
                        pr_err("metric \"%s\" has no valid label for path \"%s\"\n", name, m->path);
                        return -EINVAL;
                }
        }

        return 0;
}

static int metric_set_list_validate(void)
{
        struct metric_set *p;

        list_for_each_entry(p, &metric_set_list, node) {
                struct metric *m;

                if (metric_def_validate(&p->def)) {
                        p->disabled = 1;
                        continue;
                }

                list_for_each_entry(m, &p->metrics, node) {
                        if (metric_set_element_validate(m, p->def.name)) {
                                m->disabled = 1;
                                continue;
                        }
                }
        }

        return 0;
}

static int config_validate(void)
{
        metric_list_validate();
        metric_set_list_validate();

        return 0;
}

static int metric_value_get(struct metric *m)
{
        char buf[256] = { };
        FILE *file;
        int err = 0;

        file = fopen(m->path, "r");
        if (file == NULL) {
                pr_err("failed to open \"%s\", %s\n", m->path, strerror(abs(errno)));
                return -errno;
        }

        if (fgets(buf, sizeof(buf), file) == NULL) {
                pr_err("failed to read \"%s\", %s\n", m->path, strerror(abs(errno)));
                return -errno;
        }

        m->val = strtod(buf, NULL);
        if (errno == ERANGE) {
                pr_err("failed to parse \"%s\" into data\n", m->path);
                err = -ERANGE;
        }

        fclose(file);

        return err;
}

static int metric_value_expr_compute(struct metric *m)
{
        char expr[256] = {};
        int err = 0;

        snprintf(expr, sizeof(expr), m->expr, m->val);

        m->val = te_interp(expr, &err);

        if (err) {
                pr_err("failed to run expr \"%s\" for metric \"%s\"\n", m->expr, m->def.name);
                m->val = NAN;
        }

        return err;
}

static int metric_list_refresh(void)
{
        struct metric *p;

        list_for_each_entry(p, &metric_list, node) {
                if (p->disabled)
                        continue;

                if (metric_value_get(p))
                        continue;

                if (!isnan(p->val) && p->expr) {
                        metric_value_expr_compute(p);
                }

                {
                        prom_metric *m = prom_metric_create_or_get(&metric_set, &p->def, 0);
                        if (m)
                                m->value = p->val;
                }
        }

        return 0;
}

static int metric_set_list_refresh(void)
{
        struct metric_set *s;

        list_for_each_entry(s, &metric_set_list, node) {
                struct metric *m;

                if (s->disabled)
                        continue;

                list_for_each_entry(m, &s->metrics, node) {
                        if (m->disabled)
                                continue;

                        if (metric_value_get(m))
                                m->val = NAN;

                        if (!isnan(m->val) && m->expr) {
                                metric_value_expr_compute(m);
                        }

                        {
                                prom_label labels[PROM_MAX_LABELS] = {};
                                prom_metric *_m;
                                int n = 0;
                                struct metric_label *p;

                                list_for_each_entry(p, &m->labels, node) {
                                        memcpy(&labels[n], &p->l, sizeof(p->l));
                                        n++;
                                }

                                _m = prom_label_metric_create_or_get(&metric_set, &s->def, n, labels);
                                if (_m)
                                        _m->value = m->val;
                        }
                }
        }

        return 0;
}

static int prom_on_http_get(prom_server *srv, void *arg)
{
        metric_list_refresh();
        metric_set_list_refresh();

        prom_commit_start(srv);
        prom_commit(srv, &metric_set);
        prom_commit_end(srv);

        return 0;
}

static void metric_list_register(void)
{
        struct metric *p;

        list_for_each_entry(p, &metric_list, node) {
                prom_metric_register(&metric_set, &p->def);
        }
}

static void metric_set_list_register(void)
{
        struct metric_set *p;

        list_for_each_entry(p, &metric_set_list, node) {
                prom_metric_register(&metric_set, &p->def);
        }
}

static void prom_srv_run(void)
{
        pr_info("prometheus metric server running at %s:%u\n", listen_addr, listen_port);
        prom_run(&prom_srv);
}

static int prom_srv_init(void)
{
        int err;

        if ((err = prom_init(&prom_srv, listen_addr, listen_port))) {
                pr_err("failed to start prometheus metric server at %s:%u\n", listen_addr, listen_port);
                return err;
        }

        prom_server_on_http_get_cb(&prom_srv, prom_on_http_get, NULL);

        metric_list_register();
        metric_set_list_register();

        return err;
}

static void prom_srv_deinit(void)
{
        prom_deinit(&prom_srv);
        prom_metric_set_deinit(&metric_set);
}

static void go_exit(void)
{
        // prevent enter again
        if (__sync_bool_compare_and_swap(&g_should_exit, 0, 1) == 0)
                return;

        pr_info("enter\n");

        prom_stop(&prom_srv);

        alarm(1);
}

static void signal_handler(int sig_no)
{
        switch (sig_no) {
        case SIGALRM:
                break;

        case SIGTERM:
        case SIGKILL:
        case SIGINT:
                go_exit();
                break;

        case SIGUSR1:
                break;

        case SIGUSR2:
                break;

        default:
                break;
        }
}

int main(int argc, char *argv[])
{
        int err;

        setbuf(stdout, NULL);
        setbuf(stderr, NULL);

        signal(SIGALRM, signal_handler);
        signal(SIGKILL, signal_handler);
        signal(SIGTERM, signal_handler);
        signal(SIGINT,  signal_handler);

        if ((err = lopts_parse(argc, argv, NULL)))
                return err;

        if ((err = config_root_key_create(&jkey_root)))
                return err;

        pr_info("json config: %s\n", config_json);

        if ((err = jbuf_load(&jkey_root, config_json)))
                return err;

        config_validate();

        pr_info("loaded config:\n");
        jbuf_traverse_print(&jkey_root);

        if (list_empty(&metric_list) && list_empty(&metric_set_list)) {
                pr_err("no metrics have been loaded\n");
                return -ENODATA;
        }

        if ((err = prom_srv_init()))
                return err;

        prom_srv_run();

        prom_srv_deinit();

        jbuf_deinit(&jkey_root);

        return err;
}