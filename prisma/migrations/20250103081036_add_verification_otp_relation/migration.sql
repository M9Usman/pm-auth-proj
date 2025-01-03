/*
  Warnings:

  - A unique constraint covering the columns `[otp,userId]` on the table `VerificationOtp` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `userId` to the `VerificationOtp` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "VerificationOtp" ADD COLUMN     "userId" INTEGER NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "VerificationOtp_otp_userId_key" ON "VerificationOtp"("otp", "userId");

-- AddForeignKey
ALTER TABLE "VerificationOtp" ADD CONSTRAINT "VerificationOtp_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
