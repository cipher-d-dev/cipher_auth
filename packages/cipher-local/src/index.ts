import bcrypt from "bcrypt";
import { Model } from "mongoose";
import cipher_auth from "../../core/src";
import CipherLocal from "./CipherLocal";

/**
 * Make this a standard local strategy logic
 * / export the CipherLocal for developer customizability
 */

// This creates a Local Strategy Logic with little flexibility

declare global {
  namespace Express {
    interface User {
      id: any;
    }
  }
}


class MongooseCipherAuthLocalStrategy {
  private userModel: Model<any>;
  private uniqueField: string = "username";
  private passwordField: string = "password";
  constructor(
    userModel: Model<any>,
    uniqueField: string = "username",
    passwordField: string = "password",
  ) {
    this.userModel = userModel;
    this.uniqueField = uniqueField;
    this.passwordField = passwordField;
  }

  initialize() {
    cipher_auth.use(
      new CipherLocal(
        {
          usernameField: this.uniqueField,
          passwordField: this.passwordField,
        },
        async (identifier: string, password: string, done: any) => {
          try {
            //  Passport will populate the identifier and the developer has the this.uniqueField

            const user = await this.userModel.findOne({
              [this.uniqueField]: identifier,
            });
            if (!user) {
              throw new Error("User not found");
            }
            const passwordValidity = await bcrypt.compare(
              password,
              user?.password,
            );

            if (!passwordValidity) throw new Error("Invalid Credentials");

            return done(null, user);
          } catch (e) {
            return done(e, false);
          }
        },
      ),
    );
  }

  cipherSerialize() {
    return cipher_auth.serializeUser((user, done) => {
      done(null, user?.id);
    });
  }

  cipherDeserialize() {
    return cipher_auth.deserializeUser(async (id, done) => {
      try {
        const findUser = await this.userModel.findById(id);
        if (!findUser) throw new Error("User not found");
        done(null, findUser);
      } catch (e) {
        done(e, false);
      }
    });
  }
}

export default { CipherLocal, MongooseCipherAuthLocalStrategy };
