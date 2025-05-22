import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { authConfig } from "./auth.config";
import { z } from "zod";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcryptjs";
import postgres from "postgres";

const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        // Validate credentials format
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsedCredentials.success) {
          // Credentials format invalid
          return null;
        }

        const { email, password } = parsedCredentials.data;

        // Fetch user by email
        const user = await getUser(email);
        if (!user) {
          // No user found with this email
          return null;
        }

        // Compare entered password with hashed password
        const passwordsMatch = await bcrypt.compare(password, user.password);
        if (!passwordsMatch) {
          // Password does not match
          return null;
        }

        // Password matches, return user to log in
        return user;
      },
    }),
  ],
});
