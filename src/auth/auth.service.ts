import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import axios from 'axios';
import {
  Verification,
  VerificationType,
} from '../auth/schemas/verification.schema';
import { UserService } from '../user/user.service';
import { EmailSignupDto } from './dto/email-signup.dto';
import { AuthType, User } from '../user/schemas/user.schema';
import { comparePassword, hashPassword } from '../util/crypto';
import { tokenExtractor, CustomException } from '../util/http';
import { SnsSignupDto } from './dto/sns-signup-dto';
import { SnsLoginDto } from './dto/sns-login-dto';
import { Tokenblacklist } from './schemas/tokenblacklist.schema';
import { FindPasswordDto } from './dto/find-password.dto';
import { MailService } from '../mail/mail.service';
import { Request } from 'express';
import { FIND_PASSWORD_TEMPLATE, SIGNUP_TEMPLATE } from '../util/mail.template';
import { ReturnModelType } from '@typegoose/typegoose';
import { InjectModel } from 'nestjs-typegoose';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Verification)
    private readonly verificaionModel: ReturnModelType<typeof Verification>,
    @InjectModel(Tokenblacklist)
    private readonly tokenblacklistModel: ReturnModelType<
      typeof Tokenblacklist
    >,
    private readonly userService: UserService,
    private readonly mailService: MailService,
    private readonly jwtService: JwtService,
  ) {}

  async logout(req: Request): Promise<Tokenblacklist> {
    const token = tokenExtractor(req);
    const tokenblacklist = new this.tokenblacklistModel({
      token,
    });
    return await tokenblacklist.save();
  }

  login(user: User): string {
    const payload = { email: user.email, sub: user._id };
    return this.jwtService.sign(payload);
  }

  async googleLogin(
    snsLoginDto: SnsLoginDto,
  ): Promise<{ user: User; accessToken: string }> {
    const data = await this.requestGoogleOAuth(snsLoginDto.accessToken);

    const user = await this.userService.getByEmail(data.email);

    user.validateAuthType(AuthType.google);

    return {
      user,
      accessToken: this.login(user),
    };
  }

  private async requestGoogleOAuth(
    accessToken: string,
  ): Promise<GoogleRequest> {
    try {
      const { data }: { data: GoogleRequest } = await axios.get(
        `https://www.googleapis.com/oauth2/v1/userinfo?access_token=${accessToken}`,
      );
      return data;
    } catch (err) {
      throw new UnauthorizedException('This access token is invalid.');
    }
  }

  async facebookLogin(
    snsLogin: SnsLoginDto,
  ): Promise<{ user: User; accessToken: string }> {
    const data = await this.requestFacebookOAuth(snsLogin.accessToken);

    const user = await this.userService.getByEmail(data.email);

    user.validateAuthType(AuthType.facebook);

    return {
      user,
      accessToken: this.login(user),
    };
  }

  private async requestFacebookOAuth(
    accessToken: string,
  ): Promise<FacebookRequest> {
    try {
      const { data }: { data: FacebookRequest } = await axios.get(
        `https://graph.facebook.com/me?fields=name,email&access_token=${accessToken}`,
      );
      return data;
    } catch (err) {
      throw new UnauthorizedException('This access token is invalid.');
    }
  }

  async emailSignup(emailSignup: EmailSignupDto): Promise<User> {
    this.validateEmailForSignup(emailSignup.email);

    await this.verifyEmail(
      emailSignup.email,
      emailSignup.verificationCode,
      VerificationType.SIGNUP,
    );

    const hashedPassword = await hashPassword(emailSignup.password);
    const userDto = {
      ...emailSignup,
      password: hashedPassword,
      isExit: false,
      authType: 'email',
    };

    return this.userService.create(userDto);
  }

  async validateEmailForSignup(email: string) {
    const user = await this.userService.existsByEmail(email);
    if (user) {
      throw new HttpException(
        new CustomException('This email is already registered.'),
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  async googleSignup(snsSignup: SnsSignupDto): Promise<any> {
    const data = await this.requestGoogleOAuth(snsSignup.accessToken);

    this.validateEmailForSignup(data.email);

    const userDto = {
      email: data.email,
      name: data.name,
      phone: data.phone,
      authType: 'google',
      isExit: false,
    };

    return await this.userService.create(userDto);
  }

  async facebookSignup(snsSignup: SnsSignupDto): Promise<any> {
    const data = await this.requestFacebookOAuth(snsSignup.accessToken);

    this.validateEmailForSignup(data.email);

    const userDto = {
      email: data.email,
      name: data.name,
      authType: 'facebook',
      isExit: false,
    };

    return await this.userService.create(userDto);
  }

  async sendVerificationCodeForSignup(email: string): Promise<Verification> {
    const isUserExists = await this.userService.existsByEmail(email);

    if (isUserExists) {
      throw new HttpException(
        new CustomException('This email is already registered.'),
        HttpStatus.BAD_REQUEST,
      );
    }

    const verificationCode = this.getVerificationCode();

    const subject = 'signup: verification code';
    const toName = '';
    const toEmail = email;
    const fromName = process.env.MAIL_FROM_NAME;
    const fromEmail = process.env.MAIL_FROM_EMAIL;
    const mailTemplate = SIGNUP_TEMPLATE;

    await this.mailService.send(
      subject,
      toName,
      toEmail,
      fromName,
      fromEmail,
      mailTemplate,
      { verificationCode },
    );

    const savedVerification = await this.saveVerification(
      email,
      verificationCode,
      VerificationType.SIGNUP,
    );
    return savedVerification;
  }

  getVerificationCode(): number {
    return Math.floor(Math.random() * 1000000);
  }

  async saveVerification(
    email: string,
    verificationCode: number,
    verificationType: VerificationType,
  ): Promise<Verification> {
    const verification = new this.verificaionModel();
    verification.email = email;
    verification.verificationCode = verificationCode;
    verification.verificationType = verificationType;

    const savedVerification = await verification.save();
    return savedVerification;
  }

  async sendVerificationCodeForFindPassword(
    email: string,
  ): Promise<Verification> {
    const isUserExists = await this.userService.existsByEmail(email);

    if (!isUserExists) {
      throw new HttpException(
        new CustomException('This email is not registered.'),
        HttpStatus.BAD_REQUEST,
      );
    }

    const verificationCode = this.getVerificationCode();

    const subject = 'Find password: verification code';
    const toName = '';
    const toEmail = email;
    const fromName = process.env.MAIL_FROM_NAME;
    const fromEmail = process.env.MAIL_FROM_EMAIL;
    const mailTemplate = FIND_PASSWORD_TEMPLATE;

    await this.mailService.send(
      subject,
      toName,
      toEmail,
      fromName,
      fromEmail,
      mailTemplate,
      { verificationCode },
    );

    const savedVerification = await this.saveVerification(
      email,
      verificationCode,
      VerificationType.FIND_PASSWORD,
    );
    return savedVerification;
  }

  async sendVerificationCodeForChangeEmail(
    email: string,
  ): Promise<Verification> {
    const isUserExists = await this.userService.existsByEmail(email);

    if (isUserExists) {
      throw new HttpException(
        new CustomException('This email is already registered.'),
        HttpStatus.BAD_REQUEST,
      );
    }

    const verificationCode = this.getVerificationCode();

    const subject = 'Change email: verification code';
    const toName = '';
    const toEmail = email;
    const fromName = process.env.MAIL_FROM_NAME;
    const fromEmail = process.env.MAIL_FROM_EMAIL;
    const mailTemplate = FIND_PASSWORD_TEMPLATE;

    await this.mailService.send(
      subject,
      toName,
      toEmail,
      fromName,
      fromEmail,
      mailTemplate,
      { verificationCode },
    );

    const savedVerification = await this.saveVerification(
      email,
      verificationCode,
      VerificationType.CHANGE_EMAIL,
    );
    return savedVerification;
  }

  async verifyEmail(
    email: string,
    verificationCode: number,
    verificationType: VerificationType,
  ): Promise<void> {
    const verification = await this.findOneLatestVerification(
      email,
      verificationType,
    );

    if (!verification) {
      throw new HttpException(
        new CustomException('No verification code issued.'),
        HttpStatus.BAD_REQUEST,
      );
    }

    verification.validateExpireTime();

    verification.validateSameCode(verificationCode);
  }

  async findOneLatestVerification(
    email: string,
    verificationType: VerificationType,
  ): Promise<Verification> {
    const foundVerification = await this.verificaionModel
      .findOne({
        email,
        verificationType: verificationType,
      })
      .sort({ createdAt: -1 })
      .limit(1)
      .exec();
    return foundVerification;
  }

  async findPassword(findPassword: FindPasswordDto): Promise<User> {
    const user = await this.userService.getByEmail(findPassword.email);

    user.validateSnsRegistered();

    await this.verifyEmail(
      findPassword.email,
      findPassword.verificationCode,
      VerificationType.FIND_PASSWORD,
    );

    const isSamePassword = await comparePassword(
      findPassword.password,
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

    const changedUser = await this.userService.updatePassword(
      user,
      findPassword.password,
    );

    return changedUser;
  }

  async validateJwtToken(token: string): Promise<void> {
    const findToken = await this.findTokenblacklistByToken(token);

    if (findToken) {
      throw new HttpException(
        new CustomException('This token is invalid. Please login again.'),
        HttpStatus.FORBIDDEN,
      );
    }
  }

  private async findTokenblacklistByToken(
    token: string,
  ): Promise<Tokenblacklist> {
    return await this.tokenblacklistModel.findOne({ token });
  }
}

interface GoogleRequest {
  id: string;
  email: string;
  verified_email: true;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  phone?: string;
  locale: string;
}

interface FacebookRequest {
  id: string;
  email: string;
  name: string;
}
