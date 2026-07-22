// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Objective-C port of fix.c: class-method markers, whose symtab names are
// the literal "+[SismoFix leafWithDepth:]" spelling (spaces included).

#import <Foundation/Foundation.h>

@interface SismoFix : NSObject
+ (int)leafWithDepth:(int)x;
+ (int)midWithDepth:(int)x;
@end

@implementation SismoFix

+ (int)leafWithDepth:(int)x {
    int acc = 0;
    for (int i = 0; i < x; i++) acc += i * i;
    return acc;
}

+ (int)midWithDepth:(int)x {
    return [self leafWithDepth:x] + 1;
}

@end

int main(void) {
    return [SismoFix midWithDepth:100] & 0;
}
