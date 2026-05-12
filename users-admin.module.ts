import{Module}from'@nestjs/common';
import{TypeOrmModule}from'@nestjs/typeorm';
import{UsersAdminController}from'./users-admin.controller';
import{UsersAdminService}from'./users-admin.service';
import{User}from'../users/user.entity';
import{AuthModule}from'../auth/auth.module';
@Module({imports:[AuthModule,TypeOrmModule.forFeature([User])],controllers:[UsersAdminController],providers:[UsersAdminService]})
export class UsersAdminModule{}
