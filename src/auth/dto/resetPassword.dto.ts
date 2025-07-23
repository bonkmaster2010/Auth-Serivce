import { IsEmail, IsString } from "class-validator";



export class resetPasswordDto{
    @IsString()
    resetToken: string

    @IsEmail()
    email: string

    @IsString()
    newPassword: string;
}