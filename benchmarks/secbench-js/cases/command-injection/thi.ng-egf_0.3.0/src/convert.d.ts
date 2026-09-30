import type { Fn, Fn2 } from "@thi.ng/api";
import type { Node, Prefixes } from "./api";
export declare const toEGF: (nodes: Iterable<Node>, prefixes?: Prefixes, propFn?: Fn2<string, any, string> | undefined) => string;
export declare const toEGFNode: (node: Node, prefix: Fn<string, string | undefined>, propFn?: Fn2<string, any, string>) => string;
export declare const toEGFProp: (_: string, val: any) => string;
//# sourceMappingURL=convert.d.ts.map