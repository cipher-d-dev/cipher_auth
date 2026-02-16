import { Strategy as LocalStrategy } from "passport-local";
import cipher_auth from "../../core/src";
import { Strategy } from "passport";

const CipherLocal: typeof LocalStrategy = LocalStrategy;

export default CipherLocal;
