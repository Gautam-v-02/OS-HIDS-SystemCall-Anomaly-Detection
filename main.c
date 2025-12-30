/*
 * Host-Based Intrusion Detection System (HIDS)
 * Using Isolation Forest for Anomaly Detection on System Calls
 * 
 * Academic Implementation for Operating Systems Course (CSE316)
 * 
 * This implementation demonstrates:
 * - System call frequency-based feature extraction
 * - Isolation Forest algorithm for anomaly detection
 * - Intrusion classification based on anomaly scores
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

// ==================== CONFIGURATION ====================

#define MAX_SYSCALLS 20          // Number of different system calls to track
#define NUM_TREES 10             // Number of trees in Isolation Forest
#define SUBSAMPLE_SIZE 8         // Subsample size for each tree
#define MAX_TREE_DEPTH 10        // Maximum depth of isolation trees
#define ANOMALY_THRESHOLD 0.6    // Threshold for classifying as anomaly

// ==================== DATA STRUCTURES ====================

// Represents a process's system call behavior
typedef struct {
    int syscall_freq[MAX_SYSCALLS];  // Frequency of each system call
    int total_calls;                  // Total number of system calls
    char process_name[50];            // Process identifier
    int is_anomaly;                   // Ground truth (for testing)
} ProcessBehavior;

// Node in an Isolation Tree
typedef struct IsolationNode {
    int is_leaf;                      // 1 if leaf node, 0 if internal
    int split_attribute;              // Which syscall to split on
    int split_value;                  // Threshold value for split
    struct IsolationNode *left;       // Left child (< split_value)
    struct IsolationNode *right;      // Right child (>= split_value)
    int size;                         // Number of samples at this node
} IsolationNode;

// Isolation Tree
typedef struct {
    IsolationNode *root;
    int max_depth;
} IsolationTree;

// Isolation Forest
typedef struct {
    IsolationTree *trees[NUM_TREES];
    int num_trees;
    int subsample_size;
} IsolationForest;

// ==================== UTILITY FUNCTIONS ====================

// Harmonic number for anomaly score calculation
double harmonic_number(int n) {
    if (n <= 1) return 0.0;
    return log(n) + 0.5772156649;  // Euler's constant approximation
}

// Average path length of unsuccessful search in BST
double c_factor(int n) {
    if (n <= 1) return 0.0;
    return 2.0 * harmonic_number(n - 1) - (2.0 * (n - 1.0) / n);
}

// Random integer between min and max (inclusive)
int random_int(int min, int max) {
    return min + rand() % (max - min + 1);
}

// ==================== DATASET GENERATION ====================

// Generate synthetic normal process behavior
void generate_normal_behavior(ProcessBehavior *pb, const char *name) {
    strcpy(pb->process_name, name);
    pb->total_calls = 0;
    pb->is_anomaly = 0;
    
    // Normal processes have typical patterns
    // Common syscalls: read(0), write(1), open(2), close(3), fork(4)
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        if (i < 5) {
            // Frequent common syscalls
            pb->syscall_freq[i] = 50 + random_int(-10, 10);
        } else if (i < 10) {
            // Occasional syscalls
            pb->syscall_freq[i] = 10 + random_int(-5, 5);
        } else {
            // Rare syscalls
            pb->syscall_freq[i] = random_int(0, 3);
        }
        pb->total_calls += pb->syscall_freq[i];
    }
}

// Generate synthetic anomalous process behavior
void generate_anomalous_behavior(ProcessBehavior *pb, const char *name) {
    strcpy(pb->process_name, name);
    pb->total_calls = 0;
    pb->is_anomaly = 1;
    
    // Anomalous processes have unusual patterns
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        if (i >= 10) {
            // Abnormally high rare syscalls (suspicious activity)
            pb->syscall_freq[i] = 30 + random_int(-5, 15);
        } else if (i < 5) {
            // Abnormally low common syscalls
            pb->syscall_freq[i] = 5 + random_int(-2, 3);
        } else {
            pb->syscall_freq[i] = random_int(0, 10);
        }
        pb->total_calls += pb->syscall_freq[i];
    }
}

// ==================== ISOLATION TREE FUNCTIONS ====================

// Create a new isolation tree node
IsolationNode* create_node() {
    IsolationNode *node = (IsolationNode*)malloc(sizeof(IsolationNode));
    node->is_leaf = 0;
    node->split_attribute = -1;
    node->split_value = 0;
    node->left = NULL;
    node->right = NULL;
    node->size = 0;
    return node;
}

// Build isolation tree recursively
IsolationNode* build_isolation_tree(ProcessBehavior *data, int *indices, 
                                     int n, int current_depth, int max_depth) {
    IsolationNode *node = create_node();
    node->size = n;
    
    // Termination conditions: max depth or single/no samples
    if (current_depth >= max_depth || n <= 1) {
        node->is_leaf = 1;
        return node;
    }
    
    // Randomly select a feature (syscall) to split on
    node->split_attribute = random_int(0, MAX_SYSCALLS - 1);
    
    // Find min and max values for this attribute in current subset
    int min_val = data[indices[0]].syscall_freq[node->split_attribute];
    int max_val = min_val;
    
    for (int i = 1; i < n; i++) {
        int val = data[indices[i]].syscall_freq[node->split_attribute];
        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
    }
    
    // If all values are the same, make it a leaf
    if (min_val == max_val) {
        node->is_leaf = 1;
        return node;
    }
    
    // Random split value between min and max
    node->split_value = random_int(min_val, max_val);
    
    // Partition data into left and right subsets
    int *left_indices = (int*)malloc(n * sizeof(int));
    int *right_indices = (int*)malloc(n * sizeof(int));
    int left_count = 0, right_count = 0;
    
    for (int i = 0; i < n; i++) {
        int val = data[indices[i]].syscall_freq[node->split_attribute];
        if (val < node->split_value) {
            left_indices[left_count++] = indices[i];
        } else {
            right_indices[right_count++] = indices[i];
        }
    }
    
    // Recursively build left and right subtrees
    if (left_count > 0) {
        node->left = build_isolation_tree(data, left_indices, left_count, 
                                          current_depth + 1, max_depth);
    }
    if (right_count > 0) {
        node->right = build_isolation_tree(data, right_indices, right_count, 
                                           current_depth + 1, max_depth);
    }
    
    free(left_indices);
    free(right_indices);
    
    return node;
}

// Calculate path length for a single sample in a tree
double path_length(IsolationNode *node, ProcessBehavior *sample, int current_depth) {
    if (node == NULL) {
        return current_depth;
    }
    
    if (node->is_leaf) {
        // Add average path length adjustment for leaf nodes
        return current_depth + c_factor(node->size);
    }
    
    int val = sample->syscall_freq[node->split_attribute];
    
    if (val < node->split_value && node->left != NULL) {
        return path_length(node->left, sample, current_depth + 1);
    } else if (node->right != NULL) {
        return path_length(node->right, sample, current_depth + 1);
    }
    
    return current_depth;
}

// Free isolation tree memory
void free_tree(IsolationNode *node) {
    if (node == NULL) return;
    free_tree(node->left);
    free_tree(node->right);
    free(node);
}

// ==================== ISOLATION FOREST FUNCTIONS ====================

// Train Isolation Forest on dataset
IsolationForest* train_isolation_forest(ProcessBehavior *training_data, int n) {
    IsolationForest *forest = (IsolationForest*)malloc(sizeof(IsolationForest));
    forest->num_trees = NUM_TREES;
    forest->subsample_size = SUBSAMPLE_SIZE < n ? SUBSAMPLE_SIZE : n;
    
    printf("\n[TRAINING] Building Isolation Forest with %d trees...\n", NUM_TREES);
    
    for (int t = 0; t < NUM_TREES; t++) {
        // Random subsample
        int *subsample_indices = (int*)malloc(forest->subsample_size * sizeof(int));
        for (int i = 0; i < forest->subsample_size; i++) {
            subsample_indices[i] = random_int(0, n - 1);
        }
        
        // Build tree
        forest->trees[t] = (IsolationTree*)malloc(sizeof(IsolationTree));
        forest->trees[t]->max_depth = MAX_TREE_DEPTH;
        forest->trees[t]->root = build_isolation_tree(training_data, subsample_indices, 
                                                      forest->subsample_size, 0, MAX_TREE_DEPTH);
        
        free(subsample_indices);
        printf("  Tree %d built successfully\n", t + 1);
    }
    
    printf("[TRAINING] Isolation Forest training complete!\n");
    return forest;
}

// Calculate anomaly score for a sample
double anomaly_score(IsolationForest *forest, ProcessBehavior *sample) {
    double avg_path_length = 0.0;
    
    // Calculate average path length across all trees
    for (int t = 0; t < forest->num_trees; t++) {
        avg_path_length += path_length(forest->trees[t]->root, sample, 0);
    }
    avg_path_length /= forest->num_trees;
    
    // Normalize using c_factor
    double c = c_factor(forest->subsample_size);
    if (c == 0) return 0.5;
    
    // Anomaly score formula: s = 2^(-E(h(x))/c(n))
    double score = pow(2.0, -avg_path_length / c);
    
    return score;
}

// Free Isolation Forest memory
void free_forest(IsolationForest *forest) {
    for (int t = 0; t < forest->num_trees; t++) {
        free_tree(forest->trees[t]->root);
        free(forest->trees[t]);
    }
    free(forest);
}

// ==================== INTRUSION DETECTION ====================

// Detect intrusions in test data
void detect_intrusions(IsolationForest *forest, ProcessBehavior *test_data, int n) {
    printf("\n[DETECTION] Running intrusion detection...\n");
    printf("%-20s %-15s %-15s %-15s\n", "Process", "Anomaly Score", "Classification", "Ground Truth");
    printf("================================================================\n");
    
    int true_positive = 0, true_negative = 0;
    int false_positive = 0, false_negative = 0;
    
    for (int i = 0; i < n; i++) {
        double score = anomaly_score(forest, &test_data[i]);
        int predicted_anomaly = (score >= ANOMALY_THRESHOLD) ? 1 : 0;
        
        // Confusion matrix
        if (predicted_anomaly == 1 && test_data[i].is_anomaly == 1) true_positive++;
        else if (predicted_anomaly == 0 && test_data[i].is_anomaly == 0) true_negative++;
        else if (predicted_anomaly == 1 && test_data[i].is_anomaly == 0) false_positive++;
        else if (predicted_anomaly == 0 && test_data[i].is_anomaly == 1) false_negative++;
        
        printf("%-20s %-15.4f %-15s %-15s\n", 
               test_data[i].process_name,
               score,
               predicted_anomaly ? "INTRUSION" : "NORMAL",
               test_data[i].is_anomaly ? "ANOMALY" : "NORMAL");
    }
    
    // Performance metrics
    printf("\n[METRICS] Detection Performance:\n");
    printf("  True Positives:  %d\n", true_positive);
    printf("  True Negatives:  %d\n", true_negative);
    printf("  False Positives: %d\n", false_positive);
    printf("  False Negatives: %d\n", false_negative);
    
    double accuracy = (double)(true_positive + true_negative) / n;
    printf("  Accuracy: %.2f%%\n", accuracy * 100);
    
    if (true_positive + false_positive > 0) {
        double precision = (double)true_positive / (true_positive + false_positive);
        printf("  Precision: %.2f%%\n", precision * 100);
    }
    
    if (true_positive + false_negative > 0) {
        double recall = (double)true_positive / (true_positive + false_negative);
        printf("  Recall: %.2f%%\n", recall * 100);
    }
}

// ==================== MAIN PROGRAM ====================

int main() {
    srand(time(NULL));
    
    printf("======================================================\n");
    printf("  Host-Based Intrusion Detection System (HIDS)\n");
    printf("  System Call Anomaly Detection using Isolation Forest\n");
    printf("======================================================\n");
    
    // Generate training dataset (normal behavior only)
    int train_size = 20;
    ProcessBehavior *training_data = (ProcessBehavior*)malloc(train_size * sizeof(ProcessBehavior));
    
    printf("\n[DATA] Generating training dataset...\n");
    for (int i = 0; i < train_size; i++) {
        char name[50];
        sprintf(name, "train_proc_%d", i);
        generate_normal_behavior(&training_data[i], name);
    }
    printf("[DATA] Generated %d normal process behaviors for training\n", train_size);
    
    // Train Isolation Forest
    IsolationForest *forest = train_isolation_forest(training_data, train_size);
    
    // Generate test dataset (mix of normal and anomalous)
    int test_size = 10;
    ProcessBehavior *test_data = (ProcessBehavior*)malloc(test_size * sizeof(ProcessBehavior));
    
    printf("\n[DATA] Generating test dataset...\n");
    for (int i = 0; i < test_size; i++) {
        char name[50];
        sprintf(name, "test_proc_%d", i);
        
        // 60% normal, 40% anomalous
        if (i < 6) {
            generate_normal_behavior(&test_data[i], name);
        } else {
            generate_anomalous_behavior(&test_data[i], name);
        }
    }
    printf("[DATA] Generated %d test process behaviors\n", test_size);
    
    // Detect intrusions
    detect_intrusions(forest, test_data, test_size);
    
    // Cleanup
    free_forest(forest);
    free(training_data);
    free(test_data);
    
    printf("\n[COMPLETE] HIDS execution finished successfully!\n");
    printf("======================================================\n");
    
    return 0;
}