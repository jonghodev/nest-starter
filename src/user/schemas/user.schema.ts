import { HttpException, HttpStatus } from '@nestjs/common';
import { mongoose, prop } from '@typegoose/typegoose';
import { ModelType } from '@typegoose/typegoose/lib/types';
import { isEmail } from 'class-validator';
import { CustomException } from 'src/util/http';

export enum AuthType {
  'email' = 'email',
  'google' = 'google',
  'facebook' = 'facebook',
}

export class User {
  _id?: mongoose.Types.ObjectId;

  @prop({
    validate: {
      validator: (val) => isEmail(val),
      message: `{VALUE} is not a valid email`,
    },
    unique: true,
  })
  email: string;

  @prop({ required: true })
  password: string;

  @prop({ required: true })
  name: string;

  @prop({ required: true })
  phone: string;

  @prop({ required: true })
  authType: AuthType;

  @prop({ required: true })
  isExit: boolean;

  @prop()
  exitReason: string;

  validateAuthType(authType: AuthType) {
    if (this.authType !== authType) {
      throw new HttpException(
        new CustomException(
          'This email is signed up with a different login way.',
        ),
        HttpStatus.FORBIDDEN,
      );
    }
  }

  validateUserExit() {
    if (this.isExit) {
      throw new HttpException(
        new CustomException(
          'This is deleted account. Please signup to continue.',
        ),
        HttpStatus.FORBIDDEN,
      );
    }
  }

  validateSnsRegistered() {
    if (this.authType !== AuthType.email) {
      throw new HttpException(
        new CustomException(
          `This email is signed up with a SNS login, so you can't find password.`,
        ),
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  static async findByEmail(
    this: ModelType<User> & typeof User,
    email: string | RegExp,
  ): Promise<User> {
    return await this.findOne({
      email,
    }).exec();
  }

  static async existsByEmail(
    this: ModelType<User> & typeof User,
    email: string | RegExp,
  ): Promise<boolean> {
    const user = await this.findByEmail(email);
    return user ? true : false;
  }
}
