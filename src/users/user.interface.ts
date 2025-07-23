import { IsEmail, IsString, Length } from "class-validator";


export class UserIF{
    @IsString()
    id: string
    
    @IsString()
    username: string

    @IsEmail()
    email: string

    @IsString()
    password: string
}