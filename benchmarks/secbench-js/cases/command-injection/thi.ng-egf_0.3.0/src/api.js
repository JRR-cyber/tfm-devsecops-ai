import { isNode } from "@thi.ng/checks";
import { unsupported } from "@thi.ng/errors";
export const IS_NODE = isNode();
export const NODE_ONLY = () => unsupported("only available in NodeJS");
