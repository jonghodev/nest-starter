import { Module } from '@nestjs/common';
import { AuthModule } from '../auth.module';
import { AuthFacade } from './auth.facade';

// @Module({
//   imports: [AuthModule],
//   providers: [AuthFacade],
//   exports: [AuthFacade],
// })
export class FacadeModule {}
