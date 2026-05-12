import{Injectable,NotFoundException}from'@nestjs/common';
import{InjectRepository}from'@nestjs/typeorm';
import{Repository}from'typeorm';
import{User,UserRole}from'../users/user.entity';
import*as bcrypt from'bcryptjs';
@Injectable()
export class UsersAdminService{
  constructor(@InjectRepository(User)private repo:Repository<User>){}
  list(){return this.repo.find({select:['id','full_name','email','phone','role','active','created_at','last_login']});}
  async create(dto:any){const hash=await bcrypt.hash(dto.password||'BitValue2026x',12);const u=this.repo.create({full_name:dto.full_name,email:dto.email,phone:dto.phone,role:dto.role||UserRole.RIDER,password_hash:hash});return this.repo.save(u);}
  async update(id:string,dto:any){const u=await this.repo.findOne({where:{id}});if(!u)throw new NotFoundException();if(dto.password)dto.password_hash=await bcrypt.hash(dto.password,12);delete dto.password;Object.assign(u,dto);return this.repo.save(u);}
  async remove(id:string){const u=await this.repo.findOne({where:{id}});if(!u)throw new NotFoundException();u.active=false;return this.repo.save(u);}
}
