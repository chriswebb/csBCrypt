// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

using NUnit.Framework;
using csBCrypt;

namespace csBCryptTest
{

    /**
     * JUnit unit tests for BCrypt routines
     * @author Damien Miller
     * @version 0.2
     */

    [TestFixture]
    [TestOf(typeof(csBCrypt.BCrypt))]
    [Author("Chris Webb", "chriswebb@users.noreply.github.com")]
    public class TestBCrypt
    {
        System.String[][] test_vectors =
        {
            new string[] { "",
            "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
            "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." },
            new string[] { "",
            "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
            "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" },
            new string[] { "",
            "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
            "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" },
            new string[] { "",
            "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
            "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" },
            new string[] { "a",
            "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
            "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" },
            new string[] { "a",
            "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
            "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." },
            new string[] { "a",
            "$2a$10$k87L/MF28Q673VKh8/cPi.",
            "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" },
            new string[] { "a",
            "$2a$12$8NJH3LsPrANStV6XtBakCe",
            "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" },
            new string[] { "abc",
            "$2a$06$If6bvum7DFjUnE9p2uDeDu",
            "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" },
            new string[] { "abc",
            "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
            "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" },
            new string[] { "abc",
            "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
            "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" },
            new string[] { "abc",
            "$2a$12$EXRkfkdmXn2gzds2SSitu.",
            "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" },
            new string[] { "abcdefghijklmnopqrstuvwxyz",
            "$2a$06$.rCVZVOThsIa97pEDOxvGu",
            "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" },
            new string[] { "abcdefghijklmnopqrstuvwxyz",
            "$2a$08$aTsUwsyowQuzRrDqFflhge",
            "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." },
            new string[] { "abcdefghijklmnopqrstuvwxyz",
            "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
            "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" },
            new string[] { "abcdefghijklmnopqrstuvwxyz",
            "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
            "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" },
            new string[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$06$fPIsBO8qRqkjj273rfaOI.",
            "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" },
            new string[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$08$Eq2r4G/76Wv39MzSX262hu",
            "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" },
            new string[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
            "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" },
            new string[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$12$WApznUOJfkEGSmYRfnkrPO",
            "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" },
        };

        /**
         * Entry point for unit tests
         * @param args unused
         */
        //public static void main(System.String[] args)
        //{

        //}

        /**
         * Test method for 'BCrypt.hashpw(String, String)'
         */
        [Test]
        public void testHashpw()
        {
            //System.out.print("BCrypt.hashpw(): ");
            for (int i = 0; i < test_vectors.Length; i++)

            {
                System.String plain = test_vectors[i][0];
                System.String salt = test_vectors[i][1];
                System.String expected = test_vectors[i][2];
                System.String hashed = BCrypt.hashpw(plain, salt);
                Assert.AreEqual(expected, hashed);
                //System.out.print(".");
            }
            //System.out.println("");
        }

        /**
         * Test method for 'BCrypt.gensalt(int)'
         */
        [Test]
        public void testGensaltInt()
        {
            //System.out.print("BCrypt.gensalt(log_rounds):");
            for (int i = 4; i <= 12; i++)
            {
                //System.out.print(" " + i + ":");
                for (int j = 0; j < test_vectors.Length; j += 4)
                {
                    System.String plain = test_vectors[j][0];
                    System.String salt = BCrypt.gensalt(i);
                    System.String hashed1 = BCrypt.hashpw(plain, salt);
                    System.String hashed2 = BCrypt.hashpw(plain, hashed1);
                    Assert.AreEqual(hashed1, hashed2);
                    //System.out.print(".");
                }
            }
            //System.out.println("");
        }

        /**
         * Test method for 'BCrypt.gensalt()'
         */
        [Test]
        public void testGensalt()
        {
            //System.out.print("BCrypt.gensalt(): ");
            for (int i = 0; i < test_vectors.Length; i += 4)
            {
                System.String plain = test_vectors[i][0];
                System.String salt = BCrypt.gensalt();
                System.String hashed1 = BCrypt.hashpw(plain, salt);
                System.String hashed2 = BCrypt.hashpw(plain, hashed1);
                Assert.AreEqual(hashed1, hashed2);
                //System.out.print(".");
            }
           //System.out.println("");
        }

        /**
         * Test method for 'BCrypt.checkpw(String, String)'
         * expecting success
         */
        [Test]
        public void testCheckpw_success()
        {
           // System.out.print("BCrypt.checkpw w/ good passwords: ");
            for (int i = 0; i < test_vectors.Length; i++)
            {
                System.String plain = test_vectors[i][0];
                System.String expected = test_vectors[i][2];
                Assert.That(BCrypt.checkpw(plain, expected));
            //    System.out.print(".");
            }
           // System.out.println("");
        }

        /**
         * Test method for 'BCrypt.checkpw(String, String)'
         * expecting failure
         */
        [Test]
        public void testCheckpw_failure()
        {
         //   System.out.print("BCrypt.checkpw w/ bad passwords: ");
            for (int i = 0; i < test_vectors.Length; i++)
            {
                int broken_index = (i + 4) % test_vectors.Length;
                System.String plain = test_vectors[i][0];
                System.String expected = test_vectors[broken_index][2];
                Assert.That(!BCrypt.checkpw(plain, expected));
          //      System.out.print(".");
            }
         //   System.out.println("");
        }

        /**
         * Test for correct hashing of non-US-ASCII passwords
         */
        [Test]
        public void testInternationalChars()
        {
           // System.out.print("BCrypt.hashpw w/ international chars: ");
            System.String pw1 = "\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605";
            System.String pw2 = "????????";

            System.String h1 = BCrypt.hashpw(pw1, BCrypt.gensalt());
            Assert.That(!BCrypt.checkpw(pw2, h1));
          //  System.out.print(".");

            System.String h2 = BCrypt.hashpw(pw2, BCrypt.gensalt());
            Assert.That(!BCrypt.checkpw(pw1, h2));
         //   System.out.print(".");
        //    System.out.println("");
        }
    }



}