import type { IToEGFConvert, Node, NodeRef, Prefixes } from "./api";
export declare const isNode: (x: any) => x is Node;
export declare const isRef: (x: any) => x is NodeRef;
export declare const isToEGF: (x: any) => x is IToEGFConvert;
export declare const qualifiedID: (prefixes: Prefixes, id: string) => string;
export declare const defPrefixer: (prefixes: Prefixes) => (uri: string) => string | undefined;
export declare const defVocab: (uri: string) => (name?: string) => string;
//# sourceMappingURL=utils.d.ts.map