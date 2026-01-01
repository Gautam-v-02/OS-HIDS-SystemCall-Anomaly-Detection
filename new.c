#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define MAX_SYSCALLS 20
#define NUM_TREES 10
#define SUBSAMPLE_SIZE 8
#define MAX_DEPTH 10
#define THRESHOLD 0.6

typedef struct {
    int freq[MAX_SYSCALLS];
    int is_anomaly;
} Process;

typedef struct Node {
    int is_leaf, split_attr, split_val, size;
    struct Node *left, *right;
} Node;

//  Computes normalization factor c(n) used in Isolation Forest
// Helps convert path length into anomaly score
double c_factor(int n) {
    if (n <= 1) return 0.0;
    return 2.0 * (log(n - 1) + 0.5772156649) - (2.0 * (n - 1.0) / n);
}

// Builds an isolation tree recursively
// Randomly selects a system call feature and split value
Node* build_tree(Process *data, int *idx, int n, int depth) {
    Node *node = calloc(1, sizeof(Node));
    node->size = n;
    if (depth >= MAX_DEPTH || n <= 1) return (node->is_leaf = 1, node);

    int attr = rand() % MAX_SYSCALLS;
    int min = data[idx[0]].freq[attr], max = min;
    for (int i = 1; i < n; i++) {
        int v = data[idx[i]].freq[attr];
        if (v < min) min = v; if (v > max) max = v;
    }

    if (min == max) return (node->is_leaf = 1, node);
    node->split_attr = attr;
    node->split_val = min + rand() % (max - min + 1);

    int *l_idx = malloc(n * sizeof(int)), *r_idx = malloc(n * sizeof(int)), lc = 0, rc = 0;
    for (int i = 0; i < n; i++)
        (data[idx[i]].freq[attr] < node->split_val) ? (l_idx[lc++] = idx[i]) : (r_idx[rc++] = idx[i]);

    if (lc) node->left = build_tree(data, l_idx, lc, depth + 1);
    if (rc) node->right = build_tree(data, r_idx, rc, depth + 1);
    free(l_idx); free(r_idx);
    return node;
}

// Logic: Calculate path length of a sample
double get_path(Node *node, Process *p, int depth) {
    if (!node || node->is_leaf) return depth + c_factor(node ? node->size : 0);
    return (p->freq[node->split_attr] < node->split_val) ? 
            get_path(node->left, p, depth + 1) : get_path(node->right, p, depth + 1);
}

// Data Gen: Create synthetic syscall patterns
void gen_data(Process *p, int anomaly) {
    p->is_anomaly = anomaly;
    for (int i = 0; i < MAX_SYSCALLS; i++)
        p->freq[i] = anomaly ? (i > 10 ? rand() % 50 : rand() % 5) : (i < 5 ? 40 + rand() % 20 : rand() % 5);
}

int main() {
    srand(time(NULL));
    int n_train = 20, n_test = 10;
    Process *train = malloc(n_train * sizeof(Process)), *test = malloc(n_test * sizeof(Process));
    Node *forest[NUM_TREES];

    for (int i = 0; i < n_train; i++) gen_data(&train[i], 0);
    for (int t = 0; t < NUM_TREES; t++) {
        int idx[SUBSAMPLE_SIZE];
        for (int i = 0; i < SUBSAMPLE_SIZE; i++) idx[i] = rand() % n_train;
        forest[t] = build_tree(train, idx, SUBSAMPLE_SIZE, 0);
    }

    printf("HIDS Evaluation:\nScore\tPred\tActual\n---\t----\t------\n");
    for (int i = 0; i < n_test; i++) {
        gen_data(&test[i], i >= 6);
        double avg_p = 0;
        for (int t = 0; t < NUM_TREES; t++) avg_p += get_path(forest[t], &test[i], 0);
        double score = pow(2.0, -(avg_p / NUM_TREES) / c_factor(SUBSAMPLE_SIZE));
        printf("%.4f\t%s\t%s\n", score, score >= THRESHOLD ? "ALERT" : "OK", test[i].is_anomaly ? "ATTACK" : "NORMAL");
    }
    return 0;

}
