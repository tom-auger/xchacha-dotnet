namespace XChaChaDotNet.UnitTests
{
    public static class XChaChaConstants
    {
        public const int StreamHeaderLength = 24;
        public const int StreamABytes = 17;
        public const int NonceLength = 24;
        public const int KeyLength = 32;

        public const string Message = "Ladies and Gentlemen of the class of '99: If I could offer you " +
            "only one tip for the future, sunscreen would be it.";
        public static readonly byte[] Key =
            new byte[]
            {
                0x2A, 0xF9, 0x98, 0xBC, 0xCE, 0xA7, 0x11, 0xCF,
                0x53, 0x21, 0x5B, 0xEC, 0xC4, 0x5A, 0x19, 0xC8,
                0x31, 0x06, 0xF7, 0x78, 0x47, 0x99, 0x99, 0x2E,
                0x73, 0x1B, 0x97, 0xBD, 0x7C, 0x84, 0x40, 0xD9
            };
        public static readonly byte[] Nonce =
            new byte[]
            {
                0x62, 0x74, 0xFD, 0x0A,
                0xBB, 0x50, 0x7C, 0xD8,
                0x73, 0xB7, 0x40, 0x7B,
                0xDD, 0x76, 0xDF, 0x23,
                0x0C, 0x79, 0x29, 0xE8,
                0xE1, 0x5B, 0x30, 0x71
            };
    }
}