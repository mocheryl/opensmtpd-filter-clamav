// Copyright 2023 Mocheryl. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//go:build !openbsd

package main

// pledgePromises restricts operation only to given promises.
func pledgePromises(p ...string) error { return nil }

// unveilReadWrite unveils file system for both reading and writing to the given
// paths.
func unveilReadWrite(u ...string) error { return nil }

// unveilAndBlock unveils file system only to the given paths.
func unveilAndBlock(u ...string) error { return nil }
