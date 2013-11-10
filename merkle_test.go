/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

package merkle

import (
    "bytes"
    "crypto/md5"
    "crypto/rand"
    "crypto/sha256"
    "errors"
    "github.com/stretchr/testify/assert"
    "hash"
    "testing"
)

// SimpleHash: does nothing

var SimpleHashData []byte

type SimpleHash struct{}

func NewSimpleHash() hash.Hash {
    return SimpleHash{}
}

func (self SimpleHash) Write(p []byte) (int, error) {
    size := self.Size()
    datalen := (len(p) / size) * size
    if len(p) == 0 || len(p)%size != 0 {
        datalen += size
    }
    data := make([]byte, datalen)
    copy(data, p)

    block := make([]byte, size)
    copy(block, data[:size])
    for i := 1; i < len(data)/size; i++ {
        _block := data[i*size : (i+1)*size]
        for j, c := range _block {
            block[j] += c
        }
    }

    SimpleHashData = append(SimpleHashData, block...)
    return size, nil
}
func (self SimpleHash) Sum(p []byte) []byte {
    p = append(p[:], SimpleHashData[:]...)
    return p
}
func (self SimpleHash) Reset() {
    SimpleHashData = nil
}
func (self SimpleHash) Size() int {
    return 32
}
func (self SimpleHash) BlockSize() int {
    return 32
}

type NotHash struct{}

func NewNotHash() hash.Hash {
    return NotHash{}
}
func (self NotHash) Write(p []byte) (int, error) {
    return 32, nil
}
func (self NotHash) Sum(p []byte) []byte {
    return p
}
func (self NotHash) Reset() {
}
func (self NotHash) Size() int {
    return 32
}
func (self NotHash) BlockSize() int {
    return 32
}

// FailingHash: always returns error on Write
type FailingHash struct {
    SucceedFor int
}

var failingHashWriteAttempts int = 0

func NewFailingHashAt(n int) FailingHash {
    failingHashWriteAttempts = 0
    return FailingHash{SucceedFor: n}
}

func NewFailingHash() FailingHash {
    return NewFailingHashAt(0)
}

func (self FailingHash) Write(p []byte) (int, error) {
    failingHashWriteAttempts += 1
    if failingHashWriteAttempts > self.SucceedFor {
        return 0, errors.New("Failed to write hash")
    } else {
        return 0, nil
    }
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

func failNotEqual(t *testing.T, label string, input interface{},
    expect interface{}, result interface{}) {
    t.Errorf("%s(%v) != %v (%v, instead)", label, input, expect, result)
}

/* Utils */

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

func TestCalculateUnbalancedNodeCount(t *testing.T) {
    inputs := [][]uint64{
        {0, 0},
        {1, 1},
        {2, 3},
        {3, 6},
        {4, 7},
        {9, 20},
        {10, 21},
        {11, 23},
        {12, 24},
        {21, 44},
        {22, 45},
    }
    for _, i := range inputs {
        height := CalculateTreeHeight(CalculateNodeCount(i[0]))
        r := CalculateUnbalancedNodeCount(height, i[0])
        if r != i[1] {
            failNotEqual(t, "CalculateUnbalancedNodeCount", i[0], i[1], r)
        }
    }
    // Powers of 2 should be the same result as CalculateNodeCount
    var i uint64 = 1
    for ; i < 32; i++ {
        size := uint64(1 << i)
        node_count := CalculateNodeCount(size)
        h := CalculateTreeHeight(node_count)
        assert.Equal(t, CalculateUnbalancedNodeCount(h, size), node_count)
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

/* Tree */

func containsNode(nodes []Node, node *Node) bool {
    /* Returns trueif a *Node is in a []Node */
    for i := 0; i < len(nodes); i++ {
        if node == &nodes[i] {
            return true
        }
    }
    return false
}

func createDummyTreeData(count, size int, use_rand bool) [][]byte {
    /* Creates an array of bytes with nonsense in them */
    data := make([][]byte, count)
    for i := 0; i < count; i++ {
        garbage := make([]byte, size)
        if use_rand {
            read := 0
            for read < size {
                n, _ := rand.Read(garbage[read:])
                read += n
            }
        } else {
            for i := 0; i < size; i++ {
                garbage[i] = byte((i + 1) % 0xFF)
            }
        }
        data[i] = garbage
    }
    return data
}

func verifyGeneratedTree(t *testing.T, tree *Tree) {
    /* Given a generated tree, confirm its state is correct */

    // Nodes should have been created
    assert.NotNil(t, tree.Nodes)
    assert.Equal(t, len(tree.Nodes), cap(tree.Nodes),
        "tree.Nodes len should equal its cap")

    // The leaves should not have children
    for _, n := range tree.Leaves() {
        assert.Nil(t, n.Left)
        assert.Nil(t, n.Right)
    }

    height := tree.Height()
    var i uint64 = height - 1
    for ; i > 0; i-- {
        // All the other nodes should have children, and their children
        // should be in the deeper level
        deeper := tree.GetNodesAtHeight(i + 1)
        row := tree.GetNodesAtHeight(i)
        for j, n := range row {
            assert.NotNil(t, n.Left, "Left child should never be nil")
            assert.Equal(t, n.Left, &deeper[j*2])
            if j == len(row)-1 && len(deeper)%2 == 1 {
                // Last node in this level should have nil right child
                // if its unbalanced
                assert.Nil(t, n.Right)
                // Its hash should be the same as the left node hash
                assert.Equal(t, n.Left.Hash, n.Hash,
                    "Left child hash should equal node hash when right child is nil")
            } else {
                assert.NotNil(t, n.Right)
                assert.Equal(t, n.Right, &deeper[j*2+1])
                assert.NotEqual(t, bytes.Equal(n.Right.Hash, n.Hash), true,
                    "Right child hash should not equal node hash")
                assert.NotEqual(t, bytes.Equal(n.Left.Hash, n.Hash), true,
                    "Left child hash should not equal node hash")
            }
        }

        // Each row should have prev/2 + prev%2 nodes
        prev := len(deeper)
        assert.Equal(t, len(row), prev/2+prev%2)
    }

    root_row := tree.GetNodesAtHeight(1)
    // The root row should exist
    assert.NotNil(t, root_row)

    // The root row should be of length 1
    assert.Equal(t, len(root_row), 1,
        "The root row should contain only 1 node")

    // the Root() should be the only item in the top row
    assert.Equal(t, tree.Root(), &root_row[0],
        "tree.Root() is not the expected node")

    // The Leaves() should the deepest row
    assert.Equal(t, len(tree.Leaves()),
        len(tree.GetNodesAtHeight(tree.Height())),
        "tree.Leaves() is not the expected row")
}

func verifyInitialState(t *testing.T, tree *Tree) {
    assert.Nil(t, tree.Nodes)
    assert.Nil(t, tree.Levels)
}

func TestNewNode(t *testing.T) {
    h := NewSimpleHash()
    block := createDummyTreeData(1, h.Size(), true)[0]
    n, err := NewNode(h, block)
    assert.Nil(t, err)
    assert.Equal(t, bytes.Equal(n.Hash, block), true)

    // Any nil argument should return blank node, no error
    n, err = NewNode(nil, nil)
    assert.Nil(t, err)
    assert.Nil(t, n.Hash, nil)
    n, err = NewNode(nil, block)
    assert.Nil(t, err)
    assert.Nil(t, n.Hash, nil)
    n, err = NewNode(h, nil)
    assert.Nil(t, err)
    assert.Nil(t, n.Hash, nil)

    // Check hash error handling
    h = NewFailingHash()
    n, err = NewNode(h, block)
    assert.NotNil(t, err)
    assert.Equal(t, err.Error(), "Failed to write hash")
}

func TestNewTree(t *testing.T) {
    tree := NewTree()
    verifyInitialState(t, &tree)
}

func TestTreeUngenerated(t *testing.T) {
    tree := Tree{}
    // If data is nil, it should handle that:
    err := tree.Generate(nil, NewSimpleHash())
    assert.NotNil(t, err)
    assert.Equal(t, err.Error(), "Blocks must be non-nil")
    assert.Nil(t, tree.Leaves())
    assert.Nil(t, tree.Root())
    assert.Equal(t, tree.Height(), uint64(0))
    assert.Nil(t, tree.Nodes)
}

func TestTreeGenerate(t *testing.T) {
    tree := Tree{}
    // Setup some dummy data
    block_count := 13
    block_size := 16
    data := createDummyTreeData(block_count, block_size, true)

    // Generate the tree
    err := tree.Generate(data, NewSimpleHash())
    assert.Nil(t, err)
    verifyGeneratedTree(t, &tree)

    // Generating with no blocks should return error
    err = tree.Generate(make([][]byte, 0, 1), NewSimpleHash())
    assert.NotNil(t, err)
    assert.Equal(t, err.Error(), "Empty tree")
}

func TestGenerateFailedHash(t *testing.T) {
    tree := NewTree()
    data := createDummyTreeData(16, 16, true)
    // Fail hash during the leaf generation
    err := tree.Generate(data, NewFailingHash())
    assert.NotNil(t, err)
    assert.Equal(t, err.Error(), "Failed to write hash")

    // Fail hash during internal node generation
    data = createDummyTreeData(16, 16, true)
    err = tree.Generate(data, NewFailingHashAt(20))
    assert.NotNil(t, err)
    assert.Equal(t, err.Error(), "Failed to write hash")
}

func TestGetNodesAtHeight(t *testing.T) {
    // ungenerate tree should return nil
    tree := NewTree()
    assert.Nil(t, tree.GetNodesAtHeight(1))

    count := 15
    size := 16
    data := createDummyTreeData(count, size, true)
    tree.Generate(data, NewSimpleHash())
    verifyGeneratedTree(t, &tree)

    // invalid height should return nil
    assert.Nil(t, tree.GetNodesAtHeight(0))
    assert.Nil(t, tree.GetNodesAtHeight(tree.Height()+1))

    // check valid height = 1
    nodes := tree.GetNodesAtHeight(tree.Height())
    assert.Equal(t, len(nodes), count)
    expect := tree.Nodes[:count]
    for i := 0; i < len(nodes); i++ {
        assert.Equal(t, &expect[i], &nodes[i])
    }
}

/* Benchmarks */

func generateBenchmark(b *testing.B, data [][]byte, hashf hash.Hash) {
    tree := NewTree()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        tree.Generate(data, hashf)
    }
}

func noHashBenchmark(b *testing.B, n int) {
    data := createDummyTreeData(n, 1, false)
    generateBenchmark(b, data, NewNotHash())
}

func BenchmarkGenerate_1K_Blocks_NoHash(b *testing.B) {
    noHashBenchmark(b, 1000)
}

func BenchmarkGenerate_100K_Blocks_NoHash(b *testing.B) {
    noHashBenchmark(b, 100000)
}

func BenchmarkGenerate_1M_Blocks_NoHash(b *testing.B) {
    noHashBenchmark(b, 1000000)
}

func BenchmarkGenerate_512MB_512KB_MD5(b *testing.B) {
    mb := 512
    block_size := 512 * 1024
    data := createDummyTreeData((mb*1024*1024)/block_size, block_size, false)
    generateBenchmark(b, data, md5.New())
}

func BenchmarkGenerate_512MB_512KB_SHA256(b *testing.B) {
    mb := 512
    block_size := 512 * 1024
    data := createDummyTreeData((mb*1024*1024)/block_size, block_size, false)
    generateBenchmark(b, data, sha256.New())
}

func BenchmarkGenerate_1GB_2MB_MD5(b *testing.B) {
    mb := 1024
    block_size := 2 * 1024 * 1024
    data := createDummyTreeData((mb*1024*1024)/block_size, block_size, false)
    generateBenchmark(b, data, md5.New())
}

func BenchmarkGenerate_1GB_2MB_SHA256(b *testing.B) {
    mb := 1024
    block_size := 2 * 1024 * 1024
    data := createDummyTreeData((mb*1024*1024)/block_size, block_size, false)
    generateBenchmark(b, data, sha256.New())
}
