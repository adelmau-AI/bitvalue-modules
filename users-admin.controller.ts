import{Controller,Get,Post,Patch,Delete,Param,Body,UseGuards}from'@nestjs/common';
import{AuthGuard}from'@nestjs/passport';
import{UsersAdminService}from'./users-admin.service';
@Controller('admin/users')
@UseGuards(AuthGuard('jwt'))
export class UsersAdminController{
  constructor(private s:UsersAdminService){}
  @Get()list(){return this.s.list();}
  @Post()create(@Body()b:any){return this.s.create(b);}
  @Patch(':id')update(@Param('id')id:string,@Body()b:any){return this.s.update(id,b);}
  @Delete(':id')remove(@Param('id')id:string){return this.s.remove(id);}
}
