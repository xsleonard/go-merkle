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
	Nodes       []Node
	FillerBlock []byte
}

func NewTree(_filler_block ...[]byte) Tree {
	/* Creates a tree with optional user-provided FillerBlock. Otherwise,
	defaults to DefaultFillerBlock() */
	var filler_block []byte
	if _filler_block == nil || _filler_block[0] == nil {
		filler_block = DefaultFillerBlock()
	} else {
		filler_block = _filler_block[0]
	}
	return Tree{FillerBlock: filler_block}
}

func (self *Tree) Leaves() []Node {
	/* Returns a slice of the leaf nodes in the tree, if available, else nil */
	if self.Nodes == nil {
		return nil
	}
	return self.Nodes[0 : 1<<(self.Height()-1)]
}

func (self *Tree) Root() *Node {
	/* Returns the root node of the tree, if available, else nil */
	if self.Nodes == nil {
		return nil
	}
	return &self.Nodes[len(self.Nodes)-1]
}

func (self *Tree) GetNodesAtHeight(h uint64) []Node {
	/* Returns all nodes at a given height */
	if self.Nodes == nil {
		return nil
	}
	index, length := self.getNodeBoundsAtHeight(h, self.Height())
	if index < 0 {
		return nil
	}
	return self.Nodes[index : index+length]
}

func (self *Tree) getNodeBoundsAtHeight(h uint64, max_h uint64) (index int, length int) {
	/* Returns the index and length for a slice into a linear []Node array
	at a given height */
	if h == 0 || h > max_h {
		return -1, -1
	}
	// Calculate number of previous nodes
	index = 0
	var i uint64 = 1
	for ; i < h; i++ {
		index += 1 << (max_h - i)
	}
	// Calculate number of nodes at h
	length = 1 << (max_h - h)
	return
}

func (self *Tree) Height() uint64 {
	/* Returns the height of this tree */
	return CalculateTreeHeight(uint64(len(self.Nodes)))
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
	if height == 0 {
		return errors.New("Empty tree")
	}
	nodes := make([]Node, 0, node_count)
	leaves := nodes[0:leaf_count]

	// Create the leaf nodes
	for i, block := range blocks {
		node, err := self.createNode(hashf, block)
		if err != nil {
			return err
		}
		leaves[i] = node
	}

	// Add the filler blocks to the leaves so that the tree is complete
	for i := block_count; i < leaf_count; i++ {
		node, err := self.createNode(hashf, self.FillerBlock)
		if err != nil {
			return err
		}
		leaves[i] = node
	}

	// Create each node level
	if height != 0 {
		var h uint64 = 2
		for ; h <= height; h++ {
			bindex, blength := self.getNodeBoundsAtHeight(h-1, height)
			cindex := bindex + blength
			clength := blength / 2
			below := nodes[bindex : bindex+blength]
			current := nodes[cindex : cindex+clength]
			err := self.generateNodeLevel(below, current, hashf)
			if err != nil {
				return err
			}
		}
	}
	self.Nodes = nodes[:node_count]
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

func (self *Tree) generateNodeLevel(below []Node, current []Node, hashf NewHash) error {
	/* Creates all the non-leaf nodes for a certain height. The number of nodes
	is calculated to be 1/2 the number of nodes in the lower rung.  The newly
	created nodes will reference their Left and Right children */
	data := make([]byte, 0, hashf().Size()*2)
	for i := 0; i < len(current); i++ {
		// concatenate the two children hashes and hash them
		data = below[2*i].Hash.Sum(data)
		data = below[2*i+1].Hash.Sum(data)
		node, err := self.createNode(hashf, data)
		if err != nil {
			return err
		}
		data = data[:]

		// create the new node and point to the children
		node.Left = &below[2*i]
		node.Right = &below[2*i+1]
		current[i] = node
	}
	return nil
}

func DefaultFillerBlock() []byte {
	/* Returns a zeroed 16-byte array */
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
	/* Returns true if n is a power of 2 */
	// http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
	return n != 0 && (n&(n-1)) == 0
}

func nextPowerOfTwo(n uint64) uint64 {
	/* Returns the next highest power of 2 above n, if n is not already a
	   power of 2 */
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

var log2lookup []uint64 = []uint64{
	/* Lookup table for integer log2 implementation */
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
