#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_SYSCALLS 5
#define MAX_DEPTH 10

typedef struct Node {
    int split_attr, split_val, is_leaf;
    struct Node *left, *right;
} Node;

// Simulates a process: counts of 5 different syscalls
typedef struct {
    int freq[MAX_SYSCALLS];
} Process;

// The Crux: If the process is isolated at a low depth, it's an anomaly
int get_path_length(Node* node, Process p, int depth) {
    if (node->is_leaf || depth >= MAX_DEPTH) return depth;
    
    if (p.freq[node->split_attr] < node->split_val)
        return get_path_length(node->left, p, depth + 1);
    else
        return get_path_length(node->right, p, depth + 1);
}

// Builds a random tree by picking a random syscall and a random split value
Node* build_tree(Process* data, int n, int depth) {
    Node* node = calloc(1, sizeof(Node));
    if (depth >= MAX_DEPTH || n <= 1) {
        node->is_leaf = 1;
        return node;
    }

    node->split_attr = rand() % MAX_SYSCALLS;
    node->split_val = rand() % 100; // Random split between 0-100

    // For simplicity in this "Very Simple" version, we just split the array in half
    node->left = build_tree(data, n / 2, depth + 1);
    node->right = build_tree(data, n - n / 2, depth + 1);
    return node;
}

int main() {
    srand(time(NULL));
    Process training_set[10];
    
    // 1. Generate "Normal" processes (all have similar syscall counts)
    for(int i=0; i<10; i++) 
        for(int j=0; j<MAX_SYSCALLS; j++) training_set[i].freq[j] = 50; 

    // 2. Build the Tree
    Node* root = build_tree(training_set, 10, 0);

    // 3. Test a Normal Process vs an Attack Process
    Process normal_proc = {{50, 50, 50, 50, 50}};
    Process attack_proc = {{5, 95, 5, 95, 5}}; // Very different from training data

    int normal_path = get_path_length(root, normal_proc, 0);
    int attack_path = get_path_length(root, attack_proc, 0);

    printf("Normal Process Path Length: %d (Deep = Normal)\n", normal_path);
    printf("Attack Process Path Length: %d (Shallow = Anomaly)\n", attack_path);

    if (attack_path < normal_path) printf("\nALERT: Intrusion Detected!\n");

    return 0;
}