import { ForbiddenException, Injectable } from "@nestjs/common";
import { UserIF } from "./user.interface";
import {v4 as uuidv4} from 'uuid';
const bcrypt = require('bcrypt');

@Injectable()
export class UserService{
    private users: UserIF[] = [];

   async createUser(username: string, email: string, password: string){
        if(this.users.find((user: UserIF) => user.email === email)){
            throw new ForbiddenException("email already used please try another email")
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser: UserIF = {
            id: uuidv4(),
            username: username,
            email: email,
            password: hashedPassword
        };

        this.users.push(newUser);
        return newUser
    };

    findByEmail(email: string){
    const emailRequired = this.users.find((user: UserIF) => user.email === email);
    if(!emailRequired){throw new ForbiddenException("email not found")};
    return emailRequired
    };

}