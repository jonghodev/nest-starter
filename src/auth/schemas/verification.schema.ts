import { HttpException, HttpStatus } from '@nestjs/common';
import { prop } from '@typegoose/typegoose';
import { CustomException } from 'src/util/http';

export enum VerificationType {
  SIGNUP = 'SIGNUP',
  FIND_PASSWORD = 'FIND_PASSWORD',
  CHANGE_EMAIL = 'CHANGE_EMAIL',
}

export class Verification {
  @prop({ required: true })
  email: string;

  @prop({ required: true })
  verificationCode: number;

  @prop({ required: true })
  verificationType: VerificationType;

  createdAt: Date;
  updatedAt: Date;

  validateSameCode(verificationCode: number) {
    if (this.verificationCode != verificationCode) {
      throw new HttpException(
        new CustomException('Wrong verification code.'),
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  validateExpireTime() {
    const createdDate = new Date(this.createdAt);
    const expiredDate = createdDate.setDate(createdDate.getDay() + 1);
    const nowDate = new Date();
    if (expiredDate < nowDate.getDate()) {
      throw new HttpException(
        new CustomException('Exceed verification expire time.'),
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
