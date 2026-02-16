export interface DatabaseAdapter {
    findUser(unique: any): Promise<any | null>;
    createUser(populationData: any): Promise<any>;
}