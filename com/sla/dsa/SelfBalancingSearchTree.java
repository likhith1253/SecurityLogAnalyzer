package com.sla.dsa;

import java.util.ArrayList;
import java.util.List;

/**
 * Self-Balancing Search Tree implementation using Red-Black Tree properties.
 * Provides O(log N) insertion and search operations.
 * Provides O(log N + k) range query operations where k is the number of results.
 */
public class SelfBalancingSearchTree<T extends Comparable<T>> {
    
    private enum NodeColor { RED, BLACK }
    
    private static class TreeNode<T extends Comparable<T>> {
        T key;
        TreeNode<T> parent;
        TreeNode<T> left;
        TreeNode<T> right;
        NodeColor color;
        
        TreeNode(T key) {
            this.key = key;
            this.color = NodeColor.RED;
            this.left = null;
            this.right = null;
            this.parent = null;
        }
    }
    
    private TreeNode<T> root;
    
    public SelfBalancingSearchTree() {
        this.root = null;
    }
    
    /**
     * Insert a new element into the tree.
     * Time complexity: O(log N)
     */
    public void insert(T key) {
        TreeNode<T> newNode = new TreeNode<>(key);
        
        if (root == null) {
            root = newNode;
            root.color = NodeColor.BLACK;
            return;
        }
        
        TreeNode<T> current = root;
        TreeNode<T> parent = null;
        
        while (current != null) {
            parent = current;
            if (key.compareTo(current.key) < 0) {
                current = current.left;
            } else {
                current = current.right;
            }
        }
        
        newNode.parent = parent;
        if (key.compareTo(parent.key) < 0) {
            parent.left = newNode;
        } else {
            parent.right = newNode;
        }
        
        fixInsert(newNode);
    }
    
    /**
     * Search for an element in the tree.
     * Time complexity: O(log N)
     */
    public T search(T key) {
        TreeNode<T> node = searchNode(root, key);
        return node != null ? node.key : null;
    }
    
    /**
     * Helper method to search for a node.
     */
    private TreeNode<T> searchNode(TreeNode<T> node, T key) {
        if (node == null) {
            return null;
        }
        
        int comparison = key.compareTo(node.key);
        if (comparison == 0) {
            return node;
        } else if (comparison < 0) {
            return searchNode(node.left, key);
        } else {
            return searchNode(node.right, key);
        }
    }
    
    /**
     * Range query: Find all elements between startKey and endKey (inclusive).
     * Time complexity: O(log N + k) where k is the number of results
     */
    public List<T> rangeQuery(T startKey, T endKey) {
        List<T> result = new ArrayList<>();
        rangeQueryHelper(root, startKey, endKey, result);
        return result;
    }
    
    /**
     * Helper method for range query using in-order traversal.
     */
    private void rangeQueryHelper(TreeNode<T> node, T startKey, T endKey, List<T> result) {
        if (node == null) {
            return;
        }
        
        // If current node's key is greater than start, explore left subtree
        if (startKey.compareTo(node.key) < 0) {
            rangeQueryHelper(node.left, startKey, endKey, result);
        }
        
        // If current node is in range, add it to result
        if (startKey.compareTo(node.key) <= 0 && endKey.compareTo(node.key) >= 0) {
            result.add(node.key);
        }
        
        // If current node's key is less than end, explore right subtree
        if (endKey.compareTo(node.key) > 0) {
            rangeQueryHelper(node.right, startKey, endKey, result);
        }
    }
    
    /**
     * Get all elements in sorted order via in-order traversal.
     * Time complexity: O(N)
     */
    public List<T> inOrderTraversal() {
        List<T> result = new ArrayList<>();
        inOrderHelper(root, result);
        return result;
    }
    
    private void inOrderHelper(TreeNode<T> node, List<T> result) {
        if (node != null) {
            inOrderHelper(node.left, result);
            result.add(node.key);
            inOrderHelper(node.right, result);
        }
    }
    
    /**
     * Fix Red-Black Tree properties after insertion.
     * Ensures the tree maintains balance and color properties.
     */
    private void fixInsert(TreeNode<T> node) {
        while (node.parent != null && node.parent.color == NodeColor.RED) {
            TreeNode<T> parentNode = node.parent;
            TreeNode<T> grandparentNode = parentNode.parent;
            
            if (parentNode == grandparentNode.left) {
                TreeNode<T> uncleNode = grandparentNode.right;
                
                // Case 1: Uncle is red - recolor parent, uncle, and grandparent
                if (uncleNode != null && uncleNode.color == NodeColor.RED) {
                    parentNode.color = NodeColor.BLACK;
                    uncleNode.color = NodeColor.BLACK;
                    grandparentNode.color = NodeColor.RED;
                    node = grandparentNode; // Move up to grandparent
                } else {
                    // Case 2: Node is right child - left rotation needed first
                    if (node == parentNode.right) {
                        node = parentNode;
                        rotateLeft(node);
                    }
                    // Case 3: Node is left child - right rotation and recoloring
                    node.parent.color = NodeColor.BLACK;
                    node.parent.parent.color = NodeColor.RED;
                    rotateRight(node.parent.parent);
                }
            } else {
                // Mirror cases when parent is right child
                TreeNode<T> uncleNode = grandparentNode.left;
                
                // Case 1: Uncle is red - recolor parent, uncle, and grandparent
                if (uncleNode != null && uncleNode.color == NodeColor.RED) {
                    parentNode.color = NodeColor.BLACK;
                    uncleNode.color = NodeColor.BLACK;
                    grandparentNode.color = NodeColor.RED;
                    node = grandparentNode; // Move up to grandparent
                } else {
                    // Case 2: Node is left child - right rotation needed first
                    if (node == parentNode.left) {
                        node = parentNode;
                        rotateRight(node);
                    }
                    // Case 3: Node is right child - left rotation and recoloring
                    node.parent.color = NodeColor.BLACK;
                    node.parent.parent.color = NodeColor.RED;
                    rotateLeft(node.parent.parent);
                }
            }
        }
        root.color = NodeColor.BLACK; // Ensure root is always black
    }
    
    /**
     * Perform left rotation on the given node.
     * Before: node is parent of rightChild
     * After: rightChild is parent of node
     */
    private void rotateLeft(TreeNode<T> node) {
        TreeNode<T> rightChild = node.right;
        
        // Step 1: Turn right child's left subtree into node's right subtree
        node.right = rightChild.left;
        if (rightChild.left != null) {
            rightChild.left.parent = node;
        }
        
        // Step 2: Link node's parent to rightChild
        rightChild.parent = node.parent;
        if (node.parent == null) {
            root = rightChild;
        } else if (node == node.parent.left) {
            node.parent.left = rightChild;
        } else {
            node.parent.right = rightChild;
        }
        
        // Step 3: Put node as left child of rightChild
        rightChild.left = node;
        node.parent = rightChild;
    }
    
    /**
     * Perform right rotation on the given node.
     * Before: node is parent of leftChild
     * After: leftChild is parent of node
     */
    private void rotateRight(TreeNode<T> node) {
        TreeNode<T> leftChild = node.left;
        
        // Step 1: Turn left child's right subtree into node's left subtree
        node.left = leftChild.right;
        if (leftChild.right != null) {
            leftChild.right.parent = node;
        }
        
        // Step 2: Link node's parent to leftChild
        leftChild.parent = node.parent;
        if (node.parent == null) {
            root = leftChild;
        } else if (node == node.parent.right) {
            node.parent.right = leftChild;
        } else {
            node.parent.left = leftChild;
        }
        
        // Step 3: Put node as right child of leftChild
        leftChild.right = node;
        node.parent = leftChild;
    }
}
