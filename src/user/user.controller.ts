import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiResponse } from '../util/http';
import { ReqUser } from '../decorator/user.decorator';
import { User } from './schemas/user.schema';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/guard/jwt-auth.guard';
import { ChangeInfoDto } from './dto/change-info.dto';
import { FindPasswordDto } from './dto/find-password.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { ChangeEmailDto } from './dto/change-email.dto';
import { Request } from 'express';

@Controller('user')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @HttpCode(200)
  @Get('/check')
  async check(@ReqUser() user: User): Promise<ApiResponse> {
    return ApiResponse.create('user check success', user);
  }

  @HttpCode(200)
  @Put('/info')
  async changeInfo(
    @ReqUser() user: User,
    @Body() changeInfoDto: ChangeInfoDto,
  ): Promise<ApiResponse> {
    const changedUser = await this.userService.changeInfo(user, changeInfoDto);
    return ApiResponse.create('change info success', changedUser);
  }

  @HttpCode(200)
  @Put('/password')
  async changePassword(
    @ReqUser() user: User,
    @Body() FindPasswordDto: FindPasswordDto,
  ): Promise<ApiResponse> {
    const updatedUser = await this.userService.changePassword(
      user,
      FindPasswordDto,
    );
    return ApiResponse.create('password changed', updatedUser);
  }

  @HttpCode(200)
  @Put('/email')
  async changeEmail(
    @Req() req: Request,
    @ReqUser() user: User,
    @Body() changeEmailDto: ChangeEmailDto,
  ): Promise<ApiResponse> {
    const updatedUser = await this.userService.changeEmail(
      req,
      user,
      changeEmailDto,
    );
    return ApiResponse.create('email changed. please re-login', updatedUser);
  }

  @HttpCode(200)
  @Delete()
  async delete(
    @ReqUser() user: User,
    @Body() deleteUserDto: DeleteUserDto,
  ): Promise<ApiResponse> {
    await this.userService.delete(user, deleteUserDto.exitReason);
    return ApiResponse.create('user deleted');
  }
}
