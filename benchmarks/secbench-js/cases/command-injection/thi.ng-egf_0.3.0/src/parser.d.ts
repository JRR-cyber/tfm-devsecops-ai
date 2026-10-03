import { Node, ParseContext } from "./api";
export declare const parse: (src: string, ctx: ParseContext) => ParseContext;
/** @interal */
export declare const $parseFile: (path: string, ctx?: Partial<ParseContext> | undefined) => ParseContext;
/**
 * Parses EGF graph from given local file name, using provided options (if any)
 * to customize the parser. Returns object of graph `nodes` and `prefixes`.
 *
 * @param path
 * @param ctx
 */
export declare const parseFile: (path: string, ctx?: Partial<ParseContext> | undefined) => {
    nodes: Record<string, Node>;
    prefixes: Record<string, string>;
};
/**
 * Parses EGF graph from given string and provided options (if any) to customize
 * the parser. Returns object of graph `nodes` and `prefixes`.
 *
 * @param path
 * @param ctx
 */
export declare const parseString: (src: string, ctx?: Partial<ParseContext> | undefined) => {
    nodes: Record<string, Node>;
    prefixes: Record<string, string>;
};
//# sourceMappingURL=parser.d.ts.map