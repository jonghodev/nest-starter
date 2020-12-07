import { Injectable } from '@nestjs/common';
import { VerificationType } from '../schemas/verification.schema';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthFacade {
  constructor(private readonly authService: AuthService) {}

  async verifyEmail(
    email: string,
    verificationCode: number,
    verificationType: VerificationType,
  ): Promise<void> {
    this.authService.verifyEmail(email, verificationCode, verificationType);
  }
}
