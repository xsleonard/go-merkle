/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

package merkle

import (
	"crypto/md5"
	"errors"
	"hash"
	"testing"
)

func failNotEqual(t *testing.T, args ...interface{}) {
	t.Errorf("%s(%v) != %v (%v, instead)", args...)
}

func containsNode(nodes []Node, node *Node) bool {
	for i := 0; i < len(nodes); i++ {
		if node == &nodes[i] {
			return true
		}
	}
	return false
}

func TestCalculateTreeHeight(t *testing.T) {
	inputs := [][]uint64{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 2},
		{7, 3},
		{15, 4},
		{32, 5},
		{63, 6},
		{64, 6},
	}
	for _, i := range inputs {
		r := CalculateTreeHeight(i[0])
		if r != i[1] {
			failNotEqual(t, "CalculateTreeHeight", i[0], i[1], r)
		}
	}
}

func TestCeilLogBaseTwo(t *testing.T) {
	inputs := [][]uint64{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 2},
		{7, 3},
		{15, 4},
		{32, 5},
		{63, 6},
		{64, 6},
	}
	for _, i := range inputs {
		r := ceilLogBaseTwo(i[0])
		if r != i[1] {
			failNotEqual(t, "ceilLogBaseTwo", i[0], i[1], r)
		}
	}
}

func TestCalculateNodeCount(t *testing.T) {
	inputs := [][]uint64{
		{0, 0},
		{1, 1},
		{2, 3},
		{4, 7},
		{15, 31},
		{16, 31},
		{17, 63},
		{65535, 131071},
		{65536, 131071},
		{65537, 262143},
	}
	for _, i := range inputs {
		r := CalculateNodeCount(i[0])
		if r != i[1] {
			failNotEqual(t, "CalculateNodeCount", i[0], i[1], r)
		}
	}
}

func TestNextPowerOfTwo(t *testing.T) {
	inputs := [][]uint64{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{8, 8},
		{14, 16},
		{16, 16},
		{65535, 65536},
		{65536, 65536},
		{65537, 131072},
	}
	for _, i := range inputs {
		r := nextPowerOfTwo(i[0])
		if r != i[1] {
			failNotEqual(t, "nextPowerOfTwo", i[0], i[1], r)
		}
	}
}

func TestIsPowerOfTwo(t *testing.T) {
	type powerOfTwoResult struct {
		input  uint64
		output bool
	}
	inputs := []powerOfTwoResult{
		{0, false},
		{1, true},
		{2, true},
		{3, false},
		{4, true},
		{16, true},
		{65534, false},
		{65535, false},
		{65536, true},
		{65537, false},
		{2032131433, false},
	}
	for _, i := range inputs {
		r := isPowerOfTwo(i.input)
		if r != i.output {
			failNotEqual(t, "isPowerOfTwo", i.input, i.output, r)
		}
	}
}

func TestNewNode(t *testing.T) {
	h := md5.New()
	n := NewNode(h)
	if n.Hash != h {
		failNotEqual(t, "NewNode", h, h, n.Hash)
	}
}

func TestNewTree(t *testing.T) {
	// Create with no args
	tree := NewTree()
	verifyInitialState(t, &tree)
	verifyFillerBlock(t, &tree, DefaultFillerBlock())

	// Create with a nil arg (same as no arg, but should be handled)
	tree = NewTree(nil)
	verifyInitialState(t, &tree)
	verifyFillerBlock(t, &tree, DefaultFillerBlock())

	// Create with user-defined filler blocks
	filler := make([]byte, 16)
	for i, _ := range filler {
		filler[i] = byte(i + 1)
	}
	tree = NewTree(filler)
	verifyInitialState(t, &tree)
	verifyFillerBlock(t, &tree, filler)
}

func verifyInitialState(t *testing.T, tree *Tree) {
	if tree.Nodes != nil {
		t.Error("tree.Nodes should be nil after creating with NewTree()")
	}
	if tree.FillerBlock == nil {
		t.Error("tree.FillerBlock should be non-nil after creating with NewTree()")
	}
}

func verifyFillerBlock(t *testing.T, tree *Tree, expect []byte) {
	if len(tree.FillerBlock) != len(expect) {
		t.Log("tree.FillerBlock has wrong len")
		t.FailNow()
	}
	for i, b := range tree.FillerBlock {
		if expect[i] != b {
			t.Log("tree.FillerBlock has incorrect value(s)")
			t.FailNow()
		}
	}
}

func TestTreeUngenerated(t *testing.T) {
	tree := Tree{}
	// If data is nil, it should handle that:
	err := tree.Generate(nil, md5.New)
	if err == nil {
		t.Log("tree.Generate() expected error for nil data")
		t.FailNow()
	}
	if err.Error() != "Blocks must be non-nil" {
		t.Errorf("tree.Generate() failed with wrong error for nil blocks: %v",
			err)
	}
	if tree.Leaves() != nil {
		t.Error("tree.Leaves() should be nil")
	}
	if tree.Root() != nil {
		t.Errorf("tree.Root() should be nil")
	}
	if tree.Nodes != nil {
		t.Errorf("tree.Nodes should be nil")
	}
	err = tree.Generate(make([][]byte, 1), md5.New)
	if err == nil {
		t.Log("tree.Generate() expected error for unset FillerBlock")
		t.FailNow()
	}
	if err.Error() != "FillerBlock must be set to a non-nil value" {
		t.Errorf("tree.Generate() failed with wrong error for nil "+
			"FillerBlock: %v", err)
	}
	if tree.Leaves() != nil {
		t.Error("tree.Leaves() should be nil")
	}
	if tree.Root() != nil {
		t.Errorf("tree.Root() should be nil")
	}
	if tree.Nodes != nil {
		t.Errorf("tree.Nodes should be nil")
	}

}

func TestTreeGenerate(t *testing.T) {
	tree := Tree{FillerBlock: DefaultFillerBlock()}
	// Setup some dummy data
	block_count := 13
	block_size := 16
	data := createDummyTreeData(block_count, block_size)

	// Generate the tree
	err := tree.Generate(data, md5.New)
	if err != nil {
		t.Logf("tree.Generate error: %v", err)
		t.FailNow()
	}
	verifyGeneratedTree(t, &tree)
}

func createDummyTreeData(count, size int) [][]byte {
	/* Creates an array of bytes with nonsense in them */
	data := make([][]byte, count)
	for i := 0; i < count; i++ {
		data[i] = make([]byte, size)
		for j, _ := range data[i] {
			data[i][j] = byte(i + 1)
		}
	}
	return data
}

func verifyGeneratedTree(t *testing.T, tree *Tree) {
	/* Given a generated tree, confirm its state is correct */
	// The FillerBlock should have been created
	if tree.FillerBlock == nil {
		t.Errorf("tree.FillerBlock should have been set to a default")
	}

	// Nodes should have been created
	if tree.Nodes == nil {
		t.Logf("tree.Nodes should not be nil")
		t.FailNow()
	}

	// The leaves should not have children
	for _, n := range tree.Leaves() {
		if n.Left != nil || n.Right != nil {
			t.Error("Leaf nodes should not have any children")
		}
	}

	// All the other nodes should have children
	for i, row := range tree.Nodes[1:] {
		for _, n := range row {
			if n.Left == nil || n.Right == nil {
				t.Error("All intermediate nodes should have both children")
			}
			if !containsNode(tree.Nodes[i], n.Left) ||
				!containsNode(tree.Nodes[i], n.Right) {
				t.Error("Child nodes must be in the row below")
			}
		}
	}

	// Each row should have a power of 2 number of nodes
	for i, row := range tree.Nodes {
		if !isPowerOfTwo(uint64(len(row))) {
			t.Errorf("Each height of the tree should contain a power-of-two"+
				" number of nodes. Row %d contains %d nodes.", i, len(row))
		}
	}

	// Each row should be 1/2 the previous
	for i, row := range tree.Nodes[1:] {
		prev := len(tree.Nodes[i])
		if len(row) != prev/2 {
			t.Errorf("Each height of the tree should contain 1/2 as many "+
				"nodes as the next lower height. Row %d contains %d nodes, "+
				"but row %d contains %d.", i+1, len(row), i, prev)
		}
	}

	// The root row should be of length 1
	if len(tree.Nodes[len(tree.Nodes)-1]) != 1 {
		t.Log("The root row should contain only 1 node")
		t.FailNow()
	}

	// the Root() should be the only item in the top row
	root_row := tree.Nodes[len(tree.Nodes)-1]
	if tree.Root() != &root_row[0] {
		t.Error("tree.Root() is not the expected node")
	}

	// The Leaves() should the deepest row
	if len(tree.Leaves()) != len(tree.Nodes[0]) {
		t.Error("tree.Leaves() is not the expected row")
	}
}

// FailingHash: always returns error on Write
type FailingHash struct{}

func NewFailingHash() hash.Hash {
	return FailingHash{}
}
func (self FailingHash) Write(p []byte) (int, error) {
	return 0, errors.New("Failed to write hash")
}
func (self FailingHash) Sum(p []byte) []byte {
	return p
}
func (self FailingHash) Reset() {
}
func (self FailingHash) Size() int {
	return 0
}
func (self FailingHash) BlockSize() int {
	return 0
}

// SimpleHash: does nothing
type SimpleHash struct{}

func NewSimpleHash() hash.Hash {
	return SimpleHash{}
}
func (self SimpleHash) Write(p []byte) (int, error) {
	return 32, nil
}
func (self SimpleHash) Sum(p []byte) []byte {
	return p
}
func (self SimpleHash) Reset() {
}
func (self SimpleHash) Size() int {
	return 32
}
func (self SimpleHash) BlockSize() int {
	return 32
}

func TestGenerateFailedHash(t *testing.T) {
	tree := NewTree()
	data := createDummyTreeData(16, 16)
	err := tree.Generate(data, NewFailingHash)
	if err == nil {
		t.Log("tree.Generate() should have returned error for failed hash write")
		t.FailNow()
	}
	if err.Error() != "Failed to write hash" {
		t.Errorf("tree.Generate() failed with wrong error for failed hash: %v",
			err)
	}
}

/* Benchmarks */

// func BenchmarkGenerate(b *testing.B) {
// 	data := createDummyTreeData(count, size)
// 	h := NewSimpleHash()
// 	b.ResetTimer()
// }
