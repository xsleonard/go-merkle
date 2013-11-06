/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

package merkle

import (
	"errors"
	// "fmt"
	"hash"
)

type NewHash func() hash.Hash

type Node struct {
	Hash  hash.Hash
	Left  *Node
	Right *Node
}

func NewNode(h hash.Hash) Node {
	return Node{Hash: h}
}

type Tree struct {
	Root  *Node
	Nodes [][]Node
}

func NewTree(data [][]byte, hashf NewHash) Tree {
	t := Tree{}
	t.Generate(data, hashf)
	return t
}

func (self *Tree) Generate(data [][]byte, hashf NewHash) error {
	/* Generates the tree nodes */
	if data == nil {
		return errors.New("data must be non-nil")
	}

	node_count := CalculateNodeCount(uint64(len(data)))
	height := CalculateTreeHeight(node_count)
	nodes := make([][]Node, 0, height)
	leaves := make([]Node, 0, node_count)

	// Create the leaf nodes
	for _, block := range data {
		h := hashf()
		_, err := h.Write(block)
		if err != nil {
			return err
		}
		node := NewNode(h)
		leaves = append(leaves, node)
	}
	nodes[0] = leaves

	// Create each node level
	if height != 0 {
		var h uint64 = 0
		for ; h < height-1; h++ {
			node, err := self.generateNodeLevel(nodes[h], hashf)
			if err != nil {
				return err
			}
			nodes[h+1] = node
		}
	}
	self.Root = &nodes[len(nodes)-1][0]
	self.Nodes = nodes

	return nil
}

func (self *Tree) generateNodeLevel(nodes []Node, hashf NewHash) ([]Node, error) {
	new_nodes := make([]Node, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		// concatenate the two children hashes and hash them
		size := nodes[i].Hash.Size()
		data := make([]byte, 0, size*2)
		data = nodes[i].Hash.Sum(data)
		data = nodes[i+1].Hash.Sum(data)
		h := hashf()
		_, err := h.Write(data)
		if err != nil {
			return nil, err
		}

		// create the new node and point to the children
		n := NewNode(h)
		n.Left = &nodes[i]
		n.Right = &nodes[i+1]
		new_nodes = append(new_nodes, n)
	}
	return new_nodes, nil
}

func CalculateNodeCount(element_count uint64) uint64 {
	/* Returns the number of nodes in a Merkle tree given the number
	   of elements in the data the tree is based on */
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

func CalculateTreeHeight(node_count uint64) uint64 {
	/* Returns the height of a full, complete binary tree given node_count
	   nodes */
	return ceilLogBaseTwo(node_count)
}

func isPowerOfTwo(n uint64) bool {
	return (n != 0 && (n&(n-1)) == 0)
}

func nextPowerOfTwo(n uint64) uint64 {
	/* Returns the next highest power of 2 above n, if n is not already a
	   power of 2 */
	if n == 0 {
		return 1
	}
	// http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
	// if isPowerOfTwo(n) {
	// 	return n
	// }
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

var log2lookup []uint64 = []uint64{
	0xFFFFFFFF00000000,
	0x00000000FFFF0000,
	0x000000000000FF00,
	0x00000000000000F0,
	0x000000000000000C,
	0x0000000000000002,
}

func ceilLogBaseTwo(x uint64) uint64 {
	/* Returns the log2 value of n
	   http://stackoverflow.com/a/15327567 */
	var y uint64 = 1
	if (x & (x - 1)) == 0 {
		y = 0
	}
	var j uint64 = 32
	var i uint64 = 0

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
