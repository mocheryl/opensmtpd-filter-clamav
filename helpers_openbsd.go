// Copyright 2023 Mocheryl. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.package main

package main

import (
	"strings"

	"golang.org/x/sys/unix"
)

func pledgePromises(p ...string) error {
	if p == nil {
		return nil
	}

	return unix.PledgePromises(strings.Join(p, ` `))
}

func unveilReadWrite(u ...string) error {
	for _, v := range u {
		if err := unix.Unveil(v, `rw`); err != nil {
			return err
		}
	}

	return nil
}

func unveilAndBlock(u ...string) error {
	for _, v := range u {
		if err := unix.Unveil(v, `r`); err != nil {
			return err
		}
	}

	return unix.UnveilBlock()
}
