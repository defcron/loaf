#!/bin/bash
# identity loaf

rm -rf .loaf
./loaf.sh c . .loaf
./loaf.sh c . .loaf
./loaf.sh c .loaf .loaf
