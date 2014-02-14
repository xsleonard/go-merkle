/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

/* A fixed merkle tree implementation

Example use:

    package main

    import (
        "crypto/md5"
        "fmt"
        "github.com/xsleonard/merkle"
        "io/ioutil"
    )

    func splitData(data []byte, size int) [][]byte {
        // Splits data into an array of slices of len(size)
        count := len(data) / size
        blocks := make([][]byte, 0, count)
        for i := 0; i < count; i++ {
            block := data[i*size : (i+1)*size]
            blocks = append(blocks, block)
        }
        if len(data)%size != 0 {
            blocks = append(blocks, data[len(blocks)*size:])
        }
        return blocks
    }

    func main() {
        // Grab some data to make the tree out of, and partition
        data, err := ioutil.ReadFile("testdata") // assume testdata exists
        if err != nil {
            fmt.Println(err)
            return
        }
        blocks := splitData(data, 32)

        // Create & generate the tree
        tree := merkle.NewTree()
        err = tree.Generate(blocks, md5.New())
        if err != nil {
            fmt.Println(err)
            return
        }

        fmt.Printf("Height: %d\n", tree.Height())
        fmt.Printf("Root: %v\n", tree.Root())
        fmt.Printf("N Leaves: %v\n", len(tree.Leaves()))
        fmt.Printf("Height 2: %v\n", tree.GetNodesAtHeight(2))
    }
*/
package merkle

import (
    "errors"
    "hash"
)

// A node in the merkle tree
type Node struct {
    Hash  []byte
    Left  *Node
    Right *Node
}

// Creates a node given a hash function and data to hash
func NewNode(h hash.Hash, block []byte) (Node, error) {
    if h == nil || block == nil {
        return Node{}, nil
    }
    defer h.Reset()
    _, err := h.Write(block[:])
    if err != nil {
        return Node{}, err
    }
    return Node{Hash: h.Sum(nil)}, nil
}

// Contains all nodes
type Tree struct {
    // All nodes, linear
    Nodes []Node
    // Points to each level in the node. The first level contains the root node
    Levels [][]Node
}

func NewTree() Tree {
    return Tree{Nodes: nil, Levels: nil}
}

// Returns a slice of the leaf nodes in the tree, if available, else nil
func (self *Tree) Leaves() []Node {
    if self.Levels == nil {
        return nil
    } else {
        return self.Levels[len(self.Levels)-1]
    }
}

// Returns the root node of the tree, if available, else nil
func (self *Tree) Root() *Node {
    if self.Nodes == nil {
        return nil
    } else {
        return &self.Levels[0][0]
    }
}

// Returns all nodes at a given height, where height 1 returns a 1-element
// slice containing the root node, and a height of tree.Height() returns
// the leaves
func (self *Tree) GetNodesAtHeight(h uint64) []Node {
    if self.Levels == nil || h == 0 || h > uint64(len(self.Levels)) {
        return nil
    } else {
        return self.Levels[h-1]
    }
}

// Returns the height of this tree
func (self *Tree) Height() uint64 {
    if self.Levels == nil {
        return 0
    } else {
        return uint64(len(self.Levels))
    }
}

// Generates the tree nodes
func (self *Tree) Generate(blocks [][]byte, hashf hash.Hash) error {
    if blocks == nil {
        return errors.New("Blocks must be non-nil")
    }

    block_count := uint64(len(blocks))
    leaf_count := nextPowerOfTwo(block_count)
    node_count := CalculateNodeCount(leaf_count)
    height := CalculateTreeHeight(node_count)
    true_node_count := CalculateUnbalancedNodeCount(height, block_count)
    if height == 0 {
        return errors.New("Empty tree")
    }
    levels := make([][]Node, height)
    nodes := make([]Node, 0, true_node_count)
    leaves := nodes[0:0]

    // Create the leaf nodes
    for _, block := range blocks {
        node, err := NewNode(hashf, block)
        if err != nil {
            return err
        }
        leaves = append(leaves, node)
    }
    nodes = leaves[:]
    levels[height-1] = leaves[:]

    // Create each node level
    if height > 1 {
        h := height - 1
        for ; h > 0; h-- {
            below := levels[h]
            current := nodes[len(nodes):len(nodes)]
            current, err := self.generateNodeLevel(below, current, hashf)
            if err != nil {
                return err
            }
            levels[h-1] = current[:]
            nodes = nodes[:len(nodes)+len(current)]
        }
    }

    self.Nodes = nodes
    self.Levels = levels
    return nil
}

// Creates all the non-leaf nodes for a certain height. The number of nodes
// is calculated to be 1/2 the number of nodes in the lower rung.  The newly
// created nodes will reference their Left and Right children
func (self *Tree) generateNodeLevel(below []Node, current []Node, h hash.Hash) ([]Node, error) {
    size := h.Size()
    data := make([]byte, size*2)
    end := (len(below) + (len(below) % 2)) / 2
    for i := 0; i < end; i++ {
        // Concatenate the two children hashes and hash them, if both are
        // available, otherwise reuse the hash from the lone left node
        node := Node{}
        ileft := 2 * i
        iright := 2*i + 1
        left := &below[ileft]
        var right *Node = nil
        if len(below) > iright {
            right = &below[iright]
        }
        if right == nil {
            b := data[:size]
            copy(b, left.Hash)
            node = Node{Hash: b}
        } else {
            var err error
            copy(data[:size], below[ileft].Hash)
            copy(data[size:], below[iright].Hash)
            node, err = NewNode(h, data)
            if err != nil {
                return nil, err
            }
        }
        // Point the new node to its children and save
        node.Left = left
        node.Right = right
        current = append(current, node)

        // Reset the data slice
        data = data[:]
    }
    return current, nil
}

// Calculates the number of nodes in a binary tree unbalanced strictly on
// the right side.  Height is assumed to be equal to
// CalculateTreeHeight(CalculateNodeCount(size))
func CalculateUnbalancedNodeCount(height uint64, size uint64) uint64 {
    if isPowerOfTwo(size) {
        return CalculateNodeCount(size)
    }
    count := size
    prev := size
    i := uint64(1)
    for ; i < height; i++ {
        next := (prev + (prev % 2)) / 2
        count += next
        prev = next
    }
    return count
}

// Returns the number of nodes in a Merkle tree given the number
// of elements in the data the tree is based on
func CalculateNodeCount(element_count uint64) uint64 {
    // Pad the count to the next highest multiple of 4
    if element_count == 0 {
        return 0
    }
    element_count = nextPowerOfTwo(element_count)
    // "Full Binary Tree Theorem": The number of internal nodes is one less
    // than the number of leaf nodes.  In the Merkle tree, the number of leaf
    // nodes is equal to the number of elements to hash.
    return 2*element_count - 1
}

// Returns the height of a full, complete binary tree given node_count nodes
func CalculateTreeHeight(node_count uint64) uint64 {
    return ceilLogBaseTwo(node_count)
}

// Returns true if n is a power of 2
func isPowerOfTwo(n uint64) bool {
    // http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
    return n != 0 && (n&(n-1)) == 0
}

// Returns the next highest power of 2 above n, if n is not already a
// power of 2
func nextPowerOfTwo(n uint64) uint64 {
    if n == 0 {
        return 1
    }
    // http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
    n--
    n |= n >> 1
    n |= n >> 2
    n |= n >> 4
    n |= n >> 8
    n |= n >> 16
    n |= n >> 32
    n++
    return n
}

// Lookup table for integer log2 implementation
var log2lookup []uint64 = []uint64{
    0xFFFFFFFF00000000,
    0x00000000FFFF0000,
    0x000000000000FF00,
    0x00000000000000F0,
    0x000000000000000C,
    0x0000000000000002,
}

// Returns the log2 value of n
// See: http://stackoverflow.com/a/15327567
func ceilLogBaseTwo(x uint64) uint64 {
    y := uint64(1)
    if (x & (x - 1)) == 0 {
        y = 0
    }
    j := uint64(32)
    i := uint64(0)

    for ; i < 6; i++ {
        k := j
        if (x & log2lookup[i]) == 0 {
            k = 0
        }
        y += k
        x >>= k
        j >>= 1
    }

    return y
}
