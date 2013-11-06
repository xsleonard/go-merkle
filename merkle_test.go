/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

package merkle

import "testing"

func failNotEqual(t *testing.T, args ...interface{}) {
	t.Errorf("%s(%v) != %v (%v, instead)", args...)
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
