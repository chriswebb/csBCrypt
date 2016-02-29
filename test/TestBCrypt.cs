// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
// Copyright (c) 2016 Chris Webb <christopher.h.webb@gmail.com>
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
    
    ///<summary>NUnit unit tests for BCrypt routines</summary>
    [TestFixture]
    [TestOf(typeof(csBCrypt.BCrypt))]
    [Author("Chris Webb", "christopher.h.webb@gmail.com")]
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
        
        ///<summary>Test method for 'BCrypt.CreateHash(String, String)'</summary>
        [Test]
        public void testHashpw()
        {
            for (int i = 0; i < test_vectors.Length; i++)

            {
                System.String plain = test_vectors[i][0];
                System.String salt = test_vectors[i][1];
                System.String expected = test_vectors[i][2];
                System.String hashed = BCrypt.CreateHash(plain, salt);
                Assert.AreEqual(expected, hashed);
            }
        }
        
        ///<summary>Test method for 'BCrypt.GenerateSalt(int)'</summary>
        [Test]
        public void testGensaltInt()
        {
            for (int i = 4; i <= 12; i++)
            {
                for (int j = 0; j < test_vectors.Length; j += 4)
                {
                    System.String plain = test_vectors[j][0];
                    System.String salt = BCrypt.GenerateSalt(i);
                    System.String hashed1 = BCrypt.CreateHash(plain, salt);
                    System.String hashed2 = BCrypt.CreateHash(plain, hashed1);
                    Assert.AreEqual(hashed1, hashed2);
                }
            }
        }
        
        ///<summary>Test method for 'BCrypt.GenerateSalt()'</summary>
        [Test]
        public void testGensalt()
        {
            for (int i = 0; i < test_vectors.Length; i += 4)
            {
                System.String plain = test_vectors[i][0];
                System.String salt = BCrypt.GenerateSalt();
                System.String hashed1 = BCrypt.CreateHash(plain, salt);
                System.String hashed2 = BCrypt.CreateHash(plain, hashed1);
                Assert.AreEqual(hashed1, hashed2);
            }
        }

        ///<summary>Test method for 'BCrypt.VerifyPlaintext(String, String)'</summary>
        ///<remarks>Expecting success</remarks>
        [Test]
        public void testCheckpw_success()
        {
            for (int i = 0; i < test_vectors.Length; i++)
            {
                System.String plain = test_vectors[i][0];
                System.String expected = test_vectors[i][2];
                Assert.That(BCrypt.VerifyPlaintext(plain, expected));
            }
        }
        
        ///<summary>Test method for 'BCrypt.VerifyPlaintext(String, String)'</summary>
        ///<remarks>Expecting failure</remarks>
        [Test]
        public void testCheckpw_failure()
        {
            for (int i = 0; i < test_vectors.Length; i++)
            {
                int broken_index = (i + 4) % test_vectors.Length;
                System.String plain = test_vectors[i][0];
                System.String expected = test_vectors[broken_index][2];
                Assert.That(!BCrypt.VerifyPlaintext(plain, expected));
            }
        }
        
        ///<summary>Test for correct hashing of non-US-ASCII passwords</summary>
        [Test]
        public void testInternationalChars()
        {
            System.String pw1 = "\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605";
            System.String pw2 = "????????";

            System.String h1 = BCrypt.CreateHash(pw1, BCrypt.GenerateSalt());
            Assert.That(!BCrypt.VerifyPlaintext(pw2, h1));

            System.String h2 = BCrypt.CreateHash(pw2, BCrypt.GenerateSalt());
            Assert.That(!BCrypt.VerifyPlaintext(pw1, h2));
        }
    }



}