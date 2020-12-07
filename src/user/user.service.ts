import {
  forwardRef,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
} from '@nestjs/common';
import { ReturnModelType } from '@typegoose/typegoose';
import { Request } from 'express';
import { InjectModel } from 'nestjs-typegoose';
import { AuthService } from 'src/auth/auth.service';
import { VerificationType } from 'src/auth/schemas/verification.schema';
import { comparePassword, hashPassword } from '../util/crypto';
import { CustomException } from '../util/http';
import { ChangeEmailDto } from './dto/change-email.dto';
import { ChangeInfoDto } from './dto/change-info.dto';
import { FindPasswordDto } from './dto/find-password.dto';
import { User } from './schemas/user.schema';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User)
    private readonly userModel: ReturnModelType<typeof User>,
    @Inject(forwardRef(() => AuthService))
    private readonly authService: AuthService,
  ) {}

  async findAll(): Promise<User[]> {
    return await this.userModel.find();
  }

  async findByEmail(email: string | RegExp): Promise<User> {
    return await this.userModel.findByEmail(email);
  }

  async getByEmail(email: string | RegExp): Promise<User> {
    const user = await this.userModel.findByEmail(email);
    if (!user) {
      throw new HttpException(
        new CustomException('This email is not registered.'),
        HttpStatus.BAD_REQUEST,
      );
    }
    return user;
  }

  async existsByEmail(email: string): Promise<boolean> {
    return await this.userModel.existsByEmail(email);
  }

  async create(user: any): Promise<User> {
    const createdUser = new this.userModel(user);
    return await createdUser.save();
  }

  async save(user: User): Promise<User> {
    const savedUser = new this.userModel(user);
    return await savedUser.save();
  }

  async changeInfo(user: User, changeInfoDto: ChangeInfoDto): Promise<User> {
    user.name = changeInfoDto.name;
    user.phone = changeInfoDto.phone;
    return await this.save(user);
  }

  async changePassword(
    user: User,
    findPasswordDto: FindPasswordDto,
  ): Promise<User> {
    const isSamePassword = await comparePassword(
      findPasswordDto.password,
      user.password,
    );

    if (isSamePassword) {
      throw new HttpException(
        new CustomException(
          'Same as the old password. Please type different password',
        ),
        HttpStatus.BAD_REQUEST,
      );
    }

    return await this.updatePassword(user, findPasswordDto.password);
  }

  async updatePassword(user: User, password: string): Promise<User> {
    const hashedPassword = await hashPassword(password);
    user.password = hashedPassword;
    return await this.save(user);
  }

  async changeEmail(
    req: Request,
    user: User,
    changeEmailDto: ChangeEmailDto,
  ): Promise<User> {
    await this.authService.verifyEmail(
      changeEmailDto.email,
      changeEmailDto.verificationCode,
      VerificationType.CHANGE_EMAIL,
    );

    await this.authService.logout(req);

    return await this.updateEmail(user, changeEmailDto.email);
  }
  async updateEmail(user: User, email: string): Promise<User> {
    user.email = email;
    return await this.save(user);
  }

  async delete(user: User, exitReason: string): Promise<User> {
    user.exitReason = exitReason;
    user.isExit = true;
    return await this.save(user);
  }
}
