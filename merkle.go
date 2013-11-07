/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

package merkle

import (
	"errors"
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
	Nodes       [][]Node
	FillerBlock []byte
}

func NewTree(_filler_block ...[]byte) Tree {
	var filler_block []byte
	if _filler_block == nil || _filler_block[0] == nil {
		filler_block = DefaultFillerBlock()
	} else {
		filler_block = _filler_block[0]
	}
	return Tree{FillerBlock: filler_block}
}

func (self *Tree) Leaves() []Node {
	if self.Nodes == nil {
		return nil
	}
	return self.Nodes[0]
}

func (self *Tree) Root() *Node {
	if self.Nodes == nil {
		return nil
	}
	return &self.Nodes[len(self.Nodes)-1][0]
}

func (self *Tree) Generate(blocks [][]byte, hashf NewHash) error {
	/* Generates the tree nodes */
	if blocks == nil {
		return errors.New("Blocks must be non-nil")
	}
	if self.FillerBlock == nil {
		return errors.New("FillerBlock must be set to a non-nil value")
	}

	block_count := uint64(len(blocks))
	leaf_count := nextPowerOfTwo(block_count)
	node_count := CalculateNodeCount(leaf_count)
	height := CalculateTreeHeight(node_count)
	nodes := make([][]Node, height)
	leaves := make([]Node, 0, node_count)

	// Create the leaf nodes
	for _, block := range blocks {
		node, err := self.createNode(hashf, block)
		if err != nil {
			return err
		}
		leaves = append(leaves, node)
	}

	// Add the filler blocks to the leaves so that the tree is complete
	for i := block_count; i < leaf_count; i++ {
		node, err := self.createNode(hashf, self.FillerBlock)
		if err != nil {
			return err
		}
		leaves = append(leaves, node)
	}
	nodes[0] = leaves

	// Create each node level
	if height != 0 {
		var h uint64 = 0
		for ; h < height-1; h++ {
			level, err := self.generateNodeLevel(nodes[h], hashf)
			if err != nil {
				return err
			}
			nodes[h+1] = level
		}
	}
	self.Nodes = nodes

	return nil
}

func (self *Tree) createNode(hashf NewHash, block []byte) (Node, error) {
	/* Creates a new Node with a Hash of block []byte and adds it to the
	node array */
	h := hashf()
	_, err := h.Write(block)
	if err != nil {
		return NewNode(nil), err
	}
	return NewNode(h), nil
}

func (self *Tree) generateNodeLevel(nodes []Node, hashf NewHash) ([]Node, error) {
	/* Creates all the non-leaf nodes for a certain height. The number of nodes
	is calculated to be 1/2 the number of nodes in the lower rung.  The newly
	created nodes will reference their Left and Right children */
	new_nodes := make([]Node, len(nodes)/2)
	for i := 0; i < cap(new_nodes); i++ {
		// concatenate the two children hashes and hash them
		size := nodes[i].Hash.Size()
		data := make([]byte, 0, size*2)
		data = nodes[2*i].Hash.Sum(data)
		data = nodes[2*i+1].Hash.Sum(data)
		node, err := self.createNode(hashf, data)
		if err != nil {
			return nil, err
		}

		// create the new node and point to the children
		node.Left = &nodes[i]
		node.Right = &nodes[i+1]
		new_nodes[i] = node
	}
	return new_nodes, nil
}

func DefaultFillerBlock() []byte {
	return make([]byte, 16)
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
