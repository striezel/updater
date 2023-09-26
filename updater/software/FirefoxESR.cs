/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "d92d849db43852d742c3157d2d621199c4bbc355acd5e0872c6ce7498a6fee57a4452125f4b40755a855f1941463f43642e361375c4a9015e8cf6a0565807b58" },
                { "af", "bbe1d78afa21cbc99514f1ea8a28ed82248283cb641c10fc9bb6a075dc1a0ab80f99a8c1b7821523e2fc4a6c6d34bfa04fb00c2fe30aed9df4f74a0aba7e5c39" },
                { "an", "227ffae75f34eb2a94e1dd409a9d383b56ed4a7d04b95e89b332c511e6e6c084ebf6d8aa0f8deb39c5efbe7a7662618a6820a0b93924b23fe5ba40d257cb5916" },
                { "ar", "e50c8827fe0c3d92dcc059a0816396e2c0990436b6e84dca96494abe2cfcd44d714cd1e0738c7ea1cd4873f4f9cd032be698bfb700df8ca8f2c7cba25573aa38" },
                { "ast", "60f000fbc8edc1bc70c5ed016d426d8584e6579948893ad2805253e3380fab8382c9b070d2a6ba456da19e20da21a2057086ca22aec4d9526c1dcedc50ff8d3b" },
                { "az", "55fa69063461fbd5c502fe0a25b50345415d5d46ccdd51b28cccac7c5c84255850e731b70eef0d08457f4ac5cdcf93c7281905f1ddaa612087f29dc2396c8634" },
                { "be", "3c951f9da7686ef1095ceeff1a7df271bcc1648ae74eab875c188325fe9e9892aa56de32c5dd2eedab9c9d469b3d82f92c6ca961c1f72fbe2c4701ecb26874fe" },
                { "bg", "2f590edd758b7cf131d994ae5d04460113901e214d2da9ed8c87435a87a9c820851f2608023df69f4da83fe887e2197013063c1626f981df8bf8eb889c30a001" },
                { "bn", "24373cdf5dedafd2ca5616b1a5aae80657a9f1cc5e357933e98199f264862051eb7f09ed7419113dedc8f1306f49528e96b8bbfd3f7678e7c97a1ace97fc8dd7" },
                { "br", "18544ac88b68640dde9b9b9484432dd2f5475a6eaedebeeaf9a87c6f83176cd97cea17fc489428fca7d09bc1096e5f4b5dbca52bf450db3bb508b1a0d2257741" },
                { "bs", "a93f505d178b1d407a4ecc6c1abc1f2485eae012c214a5d758d81fff608b8b51ec1a771a13a064fb10efb477430e5c5c66f8cd2139d279744a160abd3b19a401" },
                { "ca", "67206b3c1cbd2f52e4ab6cf42bdd23ac34ab43a92a84b3e22987d06ae6a829043c7e516cbea250258ff6eadfcfe3235add60095c051d62e6512650de2560cb57" },
                { "cak", "02d1447876edf5ac7eb441e3df19b308eccbcfc66c9b1a2373336fa3864b4911c5f784195d4b5578d27dff25aa9263f53947bf8e5b277140a52f1a0314cd21e9" },
                { "cs", "0adcdd50cfdbf3fa646cba0f9ac2ece648fc5baea82689a9c24097bb03f8362d5d00bc3d2db6f1f8a88ad70e276a814b0bfbb4a5b2dd88feb6c16472953a33fc" },
                { "cy", "7e06ec658134c455511be57a2214eabd5e933b6985ac1b4ce63f430391daf8448a78bc9809dfb271c716256951bb9800d56175f713121a589cf3f68bd1e404c6" },
                { "da", "140f66e23ba672e4a065681ec9915f3d21672c3722df0dc676b1d17f0ec55c0fec0bade707659446ee7c0e15cbc45312ef04f93b9ddda01ad35b000f9931e8ec" },
                { "de", "14f4a9ff10760ef2b22900244a9384d97387720fc57573f5ce203090f1271dd61245d05251c40f6a59681ba172100cdb06fb1bf2a88fdf7a68bbda1d8f8c21ea" },
                { "dsb", "6d4f26cdd44661451099c4d153ea8620dd0f442cce9df9126b5e2989cfc81c8860a8fa0e3fe2554cb20fa10144d0992e42c86b2a38a381b7298e01a1c2d563a8" },
                { "el", "a44c4ef40e8a31b203f9b95dcef2beed5190b0b6a004858de58748843a20503e60e125ad5ee37bdf3dfba9394739fb724091e6eefaa8163326b30a8693a8a568" },
                { "en-CA", "8c46b794dca181c0232f9e51b5db4015403040f81087e151f1231a19c550354068985ee674e776f05947cb1e95c40599f14715c2121079344d22bca2d076decc" },
                { "en-GB", "6113090c76b215f46ac42352c60f747617c362672fd86a77c9a92d69d75d794cb1a2389f65e365382c1457041abf5995a5581e7fcc6e0ca85a0210049a9fdaa3" },
                { "en-US", "2ae98b183fd8981b6e26851d26405f114094ae32a4d611be608a833fd155577a42eaaa33e16ffbbd7243e9b6fcc06a6183e1fec2e1e61adfb12d7a45ce50dbfa" },
                { "eo", "645911a9de7b16fddbc97729e0ed53f6c1f537fa6c60283aa19fc5c6e986d793336c13f2ea3618541a7c155f89179df405c81eeb962832dfd2af6b3a5a47b289" },
                { "es-AR", "90c31d9456d59fad9d45c68570a591a922d06f70105cae07d2bd661b51840bb78aad15628c10b5be42744f30a8a299e7e1af4d5bf2507665e532d57a242685dc" },
                { "es-CL", "bcdaaaf140dae5f182257a4a1ccdc7fb5cbfbe3c02b372093ceb7802247e9726ed81f7225112370bf9b5734f9bc98034179bd572b3eb58da36398f47debe0028" },
                { "es-ES", "aae99fba679fc245e3dd05e7a5f07bd475b5c7c4df390353bc4db74ee30273561b9f80a178e50da2e76357362366054035f7e160fa0d5e19ffaa15e448df3a98" },
                { "es-MX", "39e3b5d3922a2921eeac2c8feb225828c29e7679a5fbf5b9e0915440a171aae52ac6e42ef6ea54331181030c080fa5060d8564c80b8e1d267e3476355646c40e" },
                { "et", "03bbcaa69e18396ad69ad276dd2b6f9c1e7a268aad2a586998d47373d4bbcfa9c984107b36958f08f7611c41b3ca787d6065429fd2be82998124ea0c6cb69fb1" },
                { "eu", "603e9e0378fd830c9c87daf3c90f62e6f78f05991e75c02626ecabf7961a5d92aebaba9eea35e76e5a5d0f4fcf50e91d1cf18480660452a5576f8073984fd11e" },
                { "fa", "9aba0541106f3f700c5be25137f6d89b5fa96f82e165c3e7a999e635cf784b5fd97c42617551272fd91eee1e64bf80b34035d6fc7d8286f19456661f695b6873" },
                { "ff", "8f0664f157f320bfbe7b74fe4fb35320e92a40026a63ce8a89667b9db6c980e300c2d6ebd0231b5d21b931674278be6a7651c94f8ed41c36680858e30f7c60d1" },
                { "fi", "8e8d75e7c00322aaa4d80c35682ce4ecec9d122d7ac84d1e4b2847bf1ddb3c4c1f2422e4389b420605c2bcd51470f09d1a945f9fadf619e282ee2ba877295cbe" },
                { "fr", "33129817a931e26c96336e56b12d5bcc7bd222c967fad7d7150da1f6cddf462540cee7a7b9f03e114ecb255561d2faddcafedd9915bb384ce26bb617fe0944ac" },
                { "fur", "a6725841ed007e27db2107709ed425b614ab9e973189e4cc21a5d77b37b70198838c39371db1684f7d40bbb021130776bba0cd63a45fdadfc2f7df2f15596367" },
                { "fy-NL", "3542ac5b4715575e8d762d70e13f062f35acbbc01c06d30e733d622351752fb73502fe1de68b2d40ad286d28862ea60045c71de3fbe82866d72ee97496b0dbbc" },
                { "ga-IE", "94f35372a77df8b868864d5e4f8261c5c22c11f1c2f4e34ff27a92085220249deeae8f717bb7e6a9806f18c468524d77346ac236df0dda151a3e9d5e81180cd1" },
                { "gd", "ae1a347047993591d6425fb2d11082058487fa2fefc845ea93a9c815fda818781a9ead3a44403d0a06bf3b44821ff4943d8323fcb68cf208151b6ddd43d4f148" },
                { "gl", "0ed1ddb3951a23a4752b711f787fcd044bda39f8637f1c9f5708c7ad432bd34bc9b51e4a2649360d3b7d4c38b97b2980203611d6a124dc1e96a4885081e49509" },
                { "gn", "f0bfa2a450e0ceba28f84e116f254bcbbdfac32f766f73bd562a619b135dad7a601914b857c16a2208ce1abc20e26350c00b53a99c1d52eddbba7deb882c90a2" },
                { "gu-IN", "9ff00391f7178fafcb702dc8e55024386bb6c6611614419fdb8b79e49e9110f19e5c061465879aae0a16b4c45dd095b6b20d9d6b6214e42a5139b9fae5c36841" },
                { "he", "f2f17fe8321dacc9ccaf89c0e8ea87ecb575072fa24ab1f4a9a000be65cd7001d5ab2be72a4c0699b20343e25d9703fe86294790aca9dece4306bfa90523e355" },
                { "hi-IN", "8cc7649a4f105746ea79d5feb8965ff2e830ef0b319cf0d492e717e3dfb1cdd71364507df6461a141c93ecfdebeebf0cfa33f37841c0fba3929fffd3d89943ec" },
                { "hr", "5003d7f9c8fc10f82322ab87f292b5e9971269a9bfdc1b1d9ed8511790d69e710fb9317da5947fdf0330085ab0773050242cc4b0d18375710e0aaf358bc23fa6" },
                { "hsb", "6d90af47f90281ec5b3b49fdf668ed0bf7088848f96e16923ecb8d4f49d795658bac2c8a7e0a0c56565d3b020b894de68f2c194b5a44a6b0fd198b6cb158e741" },
                { "hu", "911710a46a58292b1f8649715147db6e20dec2dc13e80ab2cffc815b78077fd1feeda18f289ceb8e8a93b65c4977a7167acfb40b1ea49c9d6f0feced9fe8ba56" },
                { "hy-AM", "6fb88d4c329301f7c11a7e86f4186c1544018817ae74eb427d7ee1433c90540d8a9c5d9062d6b8ddfa0967646993bbfa67d394620f5476992abd68d4bea0cebd" },
                { "ia", "ef44a3291d917666b9c1ce8aee481f91c080c4ecd419bbc0095f21fd4fc769f9ea7749bbce934651d8c78beb1b653a320facdbe365e72c6a480fbe8acf8abb95" },
                { "id", "89a670990e7f343419627c56e5bdd8400c1162868d8c7b1749cee4a938a32489636dc585d6c004939c6dc7d0ba2ec975bb6b21740714fbfeaccaa1c82bf8fa99" },
                { "is", "f16a5df721c618f2b3d64a6f1827344fea3252d4bb1c1729eba98dd2339bee95859575219cb6c73c4ab40573112f5d344178dcc8ce5bef33c1edacebdb41f882" },
                { "it", "c3747b07187a96746e16490b36af421fa7ad4f8a4dff6236d32b3b47dd5c1d8eaf935081bdf4e4065cb14a152bd5dd14a3fe9c8258ae31252b77d6bc74021adc" },
                { "ja", "cd73b28dceae152574c94fef52504be825eeb85c02a8a21875e3b7e2494bcb04ce83caf08541601949c84a2d584fe7f2515c467a480d225b87a8f44ef01d238f" },
                { "ka", "7a368cc5a96b0a035781cd530c3c7970dff496f3f4b714ee987aeb2c9cf69f50735f6bfb5605b135beb99d10460b8da8b9a7a431492ab6076349e0222d89b052" },
                { "kab", "b7549fb7e321182a074885bab87d5405afc945f53a90c9b77f4bf6e22d7e5a25bf56397094af5b4468578aaf5796524eea8d9c19fa4ce962bade6ad939c672fa" },
                { "kk", "facc90bdb42239f487923229b08024de0a27be7ecb939407a3596a1323c62be3b2a246012dfcdbe4ad56517d6957c1590a7281ed595fdd3cbabf6cb257965874" },
                { "km", "8c6a63c245f5060da773b013d5b25cf10d888b46f42883236fc3b10ff49ba019b36e442d3f22e991665cb934008dea41896912145dc3215e9f6fea6bf836b03a" },
                { "kn", "44a2a47b99d4f87614b38f75b29deed0dec4bf2189701e1ee9102566fa31e18c1ade45a99165b0468007a1d65b04c722b93229c67c395871a85de67b20d48af3" },
                { "ko", "49720d6facd94c55d0f5f8f90875333db2903e02af486eb8b06f94357031752d828e542511a5555d2082065dbae8da72bae1fb868083bee480f54ab1298222fb" },
                { "lij", "91ab392350f6e6f87572c5a7288d981bcb955c688e23f1fafdd47caca87afd77d5b68724985c8f99cb5d7cbba701d17fc7e2982934bbf55ddf1dade2fa051fff" },
                { "lt", "62c648e16233a788d481e9b0595a2b17b8ae6cfc87dee371222f7eb311487d95f53202b44226356f8fe4a1c9f757006967a0c3ca4462c7e4f541b7c3a998d455" },
                { "lv", "03a7e50bd03242a9053cf0dc82e05838a298a8b4f4d77f0b6ee9586ac98c695da0381e8a7abe2915c72f8d3a34c3e6c2b074dc709ae0f1125c183f5e13cbed84" },
                { "mk", "bb2a18c6337699efd492e955139358fdeac21e9f4b7eb72cb79ca7c386d95836b2bc74752d7ca9355ab9a76d6338e611c599a33ed29f205ca46b0c3adba58bb9" },
                { "mr", "5a9f497bd6171c5406f8553b12c05faee2b0cb8ccb8e76706d932cf298e396d6550c869a4f368ff18a27619f287cfa074333fcce54b8bc6ac6bf976958786650" },
                { "ms", "2f6839459eac914912c6e6dbf968d41ccb22a6c470ea5bee00fb07debd9d21898aac38686990fe70a13fc667fd1d2d46a9f9094e9a00d60508e51aeca3963d9e" },
                { "my", "dea076d0d6b4f86112142a8b8d5ebb98d6566e6817cc07dd7eac6458843043b67fd46f9df98110c3103d38556b64f3cdd5d67cca7915b0baa5dc8478cd964a42" },
                { "nb-NO", "070256d71316e568b8a12df335fc1d48d3972352a3f5a47a96c9c5c4adf7dee3eb4db051246c00a1f03dd656471e7463a74a74a8729bf3362fac5c357676d6a9" },
                { "ne-NP", "6d1956e72292694946b402a9452fb664880374d36bac8095697cdb32994c5e0786d943b2d5e496f6a0e39f2963e6cc9e995e60cd89eeb4c704d82ab0b4e9f317" },
                { "nl", "c0324f9461c19c7996867d31f25d8a573ecc9f25b002832b8c6c289521fa5bbd12f77afba9075190d4c45d5211d222c4f7ca25882ad9eb40cbe1b156360de519" },
                { "nn-NO", "7cc6869c9becd861ca4ec96c7fb4fbdd278d0f22796355965b9e4338dad3feb3a89eee26271c833d33d6449c9109aaff3301987acb9d2953cf369d6b3368f462" },
                { "oc", "05d13c23a1db11b3f03e2b40e7fc294769380dbbdbd97727c564b68b97476efd82a5d614ed4114c4512763919618fe6b66b32ffd2ef046512443620dfea84cff" },
                { "pa-IN", "7a5abd1cfce473d1044e5b0b533d0662ea2fbcf30b94862e52ed8e55dd865ed9f0b51bb4553c325da7315466e29e5264e855382ea1867c80967d26f37b781b5a" },
                { "pl", "c6096c98743c9cbdd716efe2d63588c3bde45c34efad512a63e5b81c5fa934e4377205361256cc016700e0c7d62f1a84de97f75bc45ff3e063a9084dfaab0caf" },
                { "pt-BR", "caf3790b97cf18a3155ea3eae428fb24a7d36d7e21cfdc521a8348fc0c86b804d5e66f861d6acffcd57a5e938d9460a29ab0fb9344f7019ddc3332d0dd2aa417" },
                { "pt-PT", "28f37269b106ced6ec24613916d2070ffe165ba0a20da53e0e92f9dbc90bb72fb52f5100af6084522a9baa942b08eeb158bec9e073f631ebbd1656837cfcd543" },
                { "rm", "0beb9fd72a3cc5dd960896d6a0282c88e67b7124146424eb40af608a7d43807a843968e679fe7156c2fc9770b5ed4ac72de7a8a766e110bfa7be463c8ba3b1cc" },
                { "ro", "c1438ebc4db12e40c3d565b87facd646ce4b6ad93ce8efd4c48caf482d4ac6b8ce8b37b0755f702c3e2013a15674b4b7b60bd665c5f2b15f1fbdbc511d7e5033" },
                { "ru", "8d19e0be9ead215deadbc1fe6e0526cdf7af6c6ac4ca56b0a8440ae03ce7ac729f672de1611556c35dc94255e81ee3fbfd25659618995f145297d4e81704e4ed" },
                { "sc", "a9c9d9354950f675f932267963105f90629aa3aba7d1de1ee481592ff7fbc8a6763defeaa6d0597c717a0f30957f9633780490076d89ef1e1acd7270959d8f60" },
                { "sco", "71c9e493df77b8e8442ea757936edf9204a5036aa46b092b18adf83860f87379cef41bc84f15946c9655c254f0a004a7697be1e5e793cc5945a3d240f1caea53" },
                { "si", "8cf0229eecba865cc540209ad7897faac2d5959d935c3ea175e39cb425bf9cb232605220afc0e4dcb6cd1570cb053226bbd0e67aa3c405f966d61b78736a12bd" },
                { "sk", "d751f884521daac4e663f6f47d88f17ccf8005a5e1e58e89189ac2811377e8eaad3dced7feb1d9ab88192c7255e0be01377a54b3b980fb1794d7006aacd5c5ef" },
                { "sl", "7783464e921580014c9027a7188163f18c5732c62f85f388cfdd1fc92ae7522bf81d84342116cb6700e6e4c3caff6a9c7f52a82057f5e01ddd6c59ff6c10b839" },
                { "son", "41adc5b1c9aa975d4f70acca7b76df1ce48e91a48542db9ec18d890d5fa7a046614dc10310b5ea17c4847a2e20e605054c05091cac825e8162610b4da0c096ae" },
                { "sq", "f25b5fd8c796c40e9b09ae3efd452a887c9d98f6f37a1e6ce5b47b8f39ec78aaa92c439342343597d9774521a0289f8de983d8484d0f44a55f26264a82f20b20" },
                { "sr", "d703f6804fdf50f16a533439f4c6ed678c834f3ac1a66c7cceda271af600e867527a36b200ed2416f89c2d93366139d108f34f06d73c6adbdd482f01aab13ad1" },
                { "sv-SE", "2ddc101ef6dc112c9eadade6a60982ccd52907b0fa98386d4316f2e50ba656d52c24a409893f694fbb24073e4fbfa2c94b4c85ac53ad04637692aba0a755d8a2" },
                { "szl", "782326290acac2d61a496555b83e0ead94cb9bda7ea050602f058a1a670012b2555b744d4c621e1902a2fce4df4b734843122deee86837ec20f0b4a9d16b68c4" },
                { "ta", "924c036f9a0b4ef152e06a996aac7810de5c44649300d80351882a54ff73b2e5ef4050cd73906c548d238b119fd39c45144f39d020c03a7acd39932bd85bb0a6" },
                { "te", "d4544500449adf89062ff64b3094a9c1a165342b2ea6e64919259c69d9d9ccee630b5b4b5257a63a6b86f9401579fea12a2f29c41f6d67da57ca9007ce4f2513" },
                { "tg", "4a3b73396af993f4e3c9c05b0c316c0a7b712972118c1b29d0a1e5c3149670bbc7287e3c44c7ad962c3b747aea2debe3278d8c2ad02d6fa50fd15ffb14af46b2" },
                { "th", "8731e0a6a59a0a1d4032a5e1ab4fe57c1860b14098f5779d51804f83b52e7a0f123c05832a9ed5a79d094c4e25db5050095205a8a17659be214184155a3ffd31" },
                { "tl", "e82a9d747d584324106c6fe88d9ca7c8496f0a0d65640bfe0609c6ed765107b8602bd7178ac76c2bf39490fe69b2e3cd3ed255b6bbe909e92880c3c899895aff" },
                { "tr", "e280edf799783fd3588c58457d7c5d6d91d583ec689011e720e8d56e531bc321ce64dbf201fdeec57deb5bccc2139a2b525d700df3e0dff20fd85b760a46514f" },
                { "trs", "27e68bb71260a484165630cec1171b2431a820750ef3fa86544bbcc3627d19d361fd1474f01b2e07257bae56005df438fe670dbd3397ed0044abf1634f9f90a0" },
                { "uk", "2f5a3d8303f3414e33edcfc013f7d0bf8aaf10ae2e9bd13cce9875776a1e31150ba098677df7ab6f0c01b06466e141099804ba8e3c6b101616d8659263219fa0" },
                { "ur", "94b38e9466837703b48f128f8c148b62b85696ac5dbc8a6e413f3a655fc39fe474976c1bdab2f88dec85f5892f2d9293071605c84f690f068eaf0e7c049ff24d" },
                { "uz", "03886048ae397b2a718587f25c7e25f4c60bf59aefe53f47b7b522cc8db6b2712ec79ab824943fdaf4b87fc2d6e8ae5aef39f75553eb72155e3bb7bf6a80d1b7" },
                { "vi", "51a2dd5c26d6334c84d93cbdf8a4de578d07eeaa8f077fded91c21a941cf6bae7601378541fcd3e1b0a3c4aa77d29c3e19a26dec93ee95a26c59ec0723641f3a" },
                { "xh", "32f298a984684ee7312f0d6d98c22627f58b1735dc8f008c792aea5f27d1b3d069f114b4078f0391afeb92ff6f98208a7a8ea7a371330130e2806d56c8d0c56c" },
                { "zh-CN", "0b3b0862e7ac791d328c660b5b64633ba92a05f39ac7d7a8f57a1610d6c4b71861f8d2c5a394cdc6b8731f265363235b039d89dd82378deabe3698416566c8d7" },
                { "zh-TW", "394589aebb96cdc3a74238561b42390a96801b0e249ab00ce612291ca19db88ebaeda9b8dfd35ed20b17491b53e2a3d3c7094eef3e2e9aa7646aaafebed4d08b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "893495ce8342bd995e5b1b44069d819be2b2fb24fdb2e9970821b00dec0b40353d5829fa34efa1e6ddd3fc8d8c38ab804a066d2a0905950dee8f00a9f5d0c060" },
                { "af", "61f0e87eeb2e46be32915e86555a9a4ce9a8850e3364f3d28d048b1dc9121011de9e7388e2b8a853220a7b7743cef063f8750256191b02ddc31d5dec716f0a97" },
                { "an", "6fa61c2b3e8ee68ec862e1947732bd0aa9ffca26a3a345fc8be226932dd3796433307256e293a17a098bf7ba7eeca4ae6feabcf9e60c4dcccecfa2bd2bf9e7cc" },
                { "ar", "1118b23042e6f5291fd411644e42ad511c9e2317c714bdcb8c4b94ba39ec893b5bf6b8a3757cb237f834e5133d1e568e16d9f18337e5c00edaf7a6df45b10e46" },
                { "ast", "c19a5c25b8d28296c11b99abd566db62c5cd0c9b3ffe72201c5293d76a9c26eb283f092a83e93409ce51b55d0bb2ccb9d561809ce12d00e852bcf04502d84804" },
                { "az", "8ac14409daed44916e956cf9f28a4b52d402ea1babd077123474d27d63ee065193227de56e8d47ff3d128f3799b5d179446170a4b2366006b7e7661d759778fb" },
                { "be", "1854439e1f38896ba04ef612c3478174b348fff64b3435353835017d218ca5d25c41a5ed3f39563f70c2765847c6488bd89209615fdcaef79abf8d1a95aaca14" },
                { "bg", "32bcbd31a45bd0e8413256d999c6b3d6324abc046fc73750151db193b985355b69a83d4e0cc0ae92c27e21d765f57e8aeeb38b722a9f83b27e3634b4d22603b5" },
                { "bn", "0350ac67403b752c33b71223d04095460d49bc47bf74cff6334946ce697fe34cb0f9230c564c68c16ad663fad63e4554b9f1271893a03b0c0996f2d11d0770ab" },
                { "br", "8311adbfa3c96f4d964331404d888feb8b9bd69febf53aa654fbfff73a8ef10c33244264baa165917d22496856f649baa4ae297eacc0a7bbd161ff46ad02d9b9" },
                { "bs", "c8abe8b7b1569614851d490dd36610a74ca56a8f06aa6e99d97fc0c3415ead0a2bf05fd3cf07a96a10157bdc2d6b1e6ae4d88011dcdd7a26d76009899e29e5cd" },
                { "ca", "3dbf0d5601676112985c41d278fb078e9ca871ac3cb373dca00d705e2503246a0df1ec3b9648533ac6a877d64fb6d58b6d855fc19441163aaf49c06b429aa187" },
                { "cak", "241f083b38c6c8af81a658bce0d1616834d5be4df1badfadf0b263c9b5a0c63477501521bbe991923a8fbc390e9dd306d44179a6b686012e7aba3c0d0a8bfd04" },
                { "cs", "b3e5f3c94715a752e1bce283a8932c435d36d9719123c1de6560bd0e2c38b53bcfc3c091e0fb5ee5d60213f1ac128ed49de7813edcaba57ea475c489e3cba52a" },
                { "cy", "334e2c5cd69adf5ca20c85a2a7a71b0c5f364da45bf2efe38569d471f615bcf027b411883cd0fa5faae05d48d1c1dd6685da59ee902121f1d8d60881ffac0894" },
                { "da", "d74783ffe981ffb077318b1f089654f5b04c000fcf38b304ea4edf1957b4c6b1e476b01b024713f0a632508f06091c7ff69d56409f7add20e665bcf011a51c48" },
                { "de", "e0fb9a0b39b828d1dea353ef62b9e454399d82ac72be7adb70d2cc81acb4c76eca2a84de87e2ffc68fc243481231f25076ceb4a3ba7a51a35c86483b21b058a9" },
                { "dsb", "6cf0d84d921bf30d4c47dfb65f686b574058748f4c2929ba8df265951ad3baeac890165c520c5b215a45814706b89ef579113da6bbbecfd3142aa1d8dcea2c76" },
                { "el", "a54f8e273b9fc121e3b6d039a8d4b16eaa02ab377d31774eba615ca235cf4af946e88d082addde84efb6cd2a926e04b50513c385f1d23e2ed1d12ffa88beb14c" },
                { "en-CA", "2202aa150cb4191cc7581e4d65e34c4326c3b9d8b137d782979c8b647deaab8e55611a7be7b892c0c725d6c6172c61d129e1a2c49203f894119797730ab89e4d" },
                { "en-GB", "84e34e526f155a69c32c63f9fab7a24ad9c5c622364a06c919ac0719e4f648a19f50cfac147d14fff5242aad8f872deb61d321b7d337499b729d24f56acd63b1" },
                { "en-US", "5293d7ee83581a8eb705d74b6542d4be3e729aa6863522135100595e36d5e96c872172b0ad8dba5b2f2f7ae2cc87bbf7a0f3798f27ce88b17bf77a8bce4d9dcb" },
                { "eo", "14878f7bdba344cd6d034d81c9c33e99202002818d1b05067ff0b85f12725a504d695b75e5e64941c2e4bcb096187c899c1f6b19ecc9dd316c5a1982080a23c2" },
                { "es-AR", "831d26b64e731d27fc42414b263d673778d2fd4a00f2b3a8cd8a8cb1adf0247550ece2ee72e1549a745908a5125b1d78bf70269d49716f1ef9923602737aa2c6" },
                { "es-CL", "2a20df43f697526fe85aeed9adaca230cc827c15ebc684ac00389b1675230a5c7a7253a6ca2ecb039cd4933f811886bc70c1db04b0a5bce5197cbe719f6b8da7" },
                { "es-ES", "537b248cadd3c78f5e4334dd30910853f9daaf3f127f67d1f23a775ccf4e7ce5fa84268794514ab9df962fb7396d373bbfdf1babcf47ef62b1f3c7b627d727bf" },
                { "es-MX", "acc6f5f361c3cc38ce73d93fc811bb04b77869739ac7ff433786c03204c378187a2452c8d1d2bf367bc301208d818f787c1829a25b6b2408ceacf9b1adae1b59" },
                { "et", "91797173727fe9a186a3e0bc39e3ef8e3713e689c3ab9b75b7a78bab7db2e17b957c8f72e3b13c77efe2760df3e563738bdf77935e331230de116601e80e4a9b" },
                { "eu", "07aa4768943de84ecf35a2b31a73d0815eeb73dd245f588bc451ec45904507d9e95ccc38a71b613919c030b142f8ce65e45d5f2b125212fa2a6c7f6d81e64fca" },
                { "fa", "3e86f6e2f02bcedefcf644a3ff02e3771f273c89b5998607d6311c8ddff394631d92e0437a58712e51bebdd06627fabfbbb660532bf755bdba802821bdfeacb8" },
                { "ff", "e7dc7fa6d89b48562decbb9d792a4eb2797844e09996c4903c380b2e357db7700e2452e6d06823f490f447213f0601fa6250c24b8ecc013042be0cd9c88a01be" },
                { "fi", "4e8803eea56c1cbd992a2f2f67d681ae66fbbb51d4f27ca8e2b7f7b6bfde77b04393370438acbe60bdf449034b6abb3ab841ec8e65bbfdafdab297b3bb6351f7" },
                { "fr", "5dc9cf301c2ddccdf80aec4d538781ce49f20d501e9102d1392993db3939050b832965bd4837eb6a6caadcda58c356690521c72b40c6e75aa6376a7b5199f670" },
                { "fur", "707acbeb5d9c0fad446979f6946e1f5d9b90160a6f694d0a1a1da272ec348df5d6da88eac8073867ee0ac72eba1af3107cbbda4e0c69359e519d60ed253410b2" },
                { "fy-NL", "d76767dc5a5ac1b7bbc4ef1cbfd174e1a51b43cbfd2ea732ff5197fa4d6a0cd10fec70e652ea26740cd7818fa09e2920f9cc57be1d76b0b308a07d30709e30d8" },
                { "ga-IE", "84fe1a2cd3a2e25ea1df3c84b1382822c0f3a98b69a67c566c5f94285183faa3806a4225b5025160ce39480278c1e6a7ba28a0af54b1c1cc53ddd4870f59caa5" },
                { "gd", "ac3cc0ae645a41123fdb7ee446ada0d25cbcbb9da201c9c57d86e8649f40fbd062bc853e72c57bb42d3b9a8791cecac4f90557bb42c0877b57c3e5e1e6e14810" },
                { "gl", "38f09e0278e09006bef59d304bed2e826118824eb0453fcb8348ec6705eaf87c33c6bda1094d3e52fe9c6cdaf58728a6c4a98cb4613cb9c19d78ac43d130088a" },
                { "gn", "60d0d0c594cc994e4f5731c185194070e1843427cf1f778b3530f09828330817b42aab25d7da7db1c3fdf480438d4ca891adad9c8fe29ddc6b3060e2e5806644" },
                { "gu-IN", "be1c03c7e50b5aa476d4ebd4f56e3c5efd2d620964a974b9e3f0d0132e7242c4f3fe360dc11fcafe73ff544dc7796e22c208bed76dc3ae18b0d85ba80acb6a4f" },
                { "he", "88904af90b19c194b315ba8493b29377093723ef76660db47f2b45e4ea4dc541cd3a7eed07433034ded98c65b8e452aaf1cfb4d2b491b0a2e647b27e0a16e925" },
                { "hi-IN", "b51fd31b45d10952dac5379e5bc6c0e95624414bdf0f6e9ca1efd918be7a4565d25e9db7a82f4129dfa32eecfa77279c654df8499c458c161f1a4d28a9ad8e45" },
                { "hr", "8fd8b8eb0a2e46e66f59af9ec7fac94198acd626cd93575428b61713da2e5715e0e19446816fdaa47789498a703d9c78fba0d7db4b606d626b928d67d6ca685b" },
                { "hsb", "f24ca53bde131320ddc04e2d5074b24028490758a11742c37e6039ed9a334444d7bd477cae2025edda8a000e00f1b882b10f9becddf7ca9fc113bfdb67aa6429" },
                { "hu", "fb8ccadff842dcb0ebd3a241efae2916e6d2dc186d66b72bd38d3508622c5391f924fc873357d2a0ef5bcc1c71b17dc9d2b3617245c19ebe966e82971b523c42" },
                { "hy-AM", "0db8a28b1b788bb439452a3a2436095f5e8236e67b7fc4ad7f858faa0dd6486ff1042c7452af91f39d065d026244666d1daa6c25d351fd4a93723016a4b2614d" },
                { "ia", "fa95a1c24fe19a6aae275532fc4203c69ea5e2940c0352a2cab875e7074815afc48d60323926f5837e4ec9577d6eb8ca05d1593b9a49841a908dacb170a360f3" },
                { "id", "a5376252ad74f854b092b65180eb61dc2fbc94cebaf1a2f15c2817c45cc8ddbe1529855861742cccba34063a029e9610ae0f42e410c766f91c1ad20862bef950" },
                { "is", "d5d9c3a1035c910944c892765934092df93a2a3e41ed87a8cfd8dbb79d7a3e9935f06a8a6c97a6cb6665a3763a13549f1c2c7d605615d771f10d4dd8a3411639" },
                { "it", "f00550cb527a2521c9bfb51f5619aee8f2b7cbb78f5a614a4b08735a48f36b16db0187e9fa394b3a780ae570074d8efc2023d633fd7087872cc6799730969c5b" },
                { "ja", "290fc2545f25127ba083ada0c8f8465839a2a69bbbb765d10a573fc388b10a4340ed691433151aafeb5583ca56204c7e295760980365d7f5b9055531a5ee8b24" },
                { "ka", "9f9e9318ba6776b26578f4425932da37521c80371e5cbce92a6318f7ed088d20cb8cf721263ca5af12e84d1b6b989b7d002251fadfe69244ced3718c57fef113" },
                { "kab", "2b43d117d429d742544d94e6d0cefd725f146d03862991e6afe64bfd131406b506441101d93e8aa84b5c305cd76714904a2bc86beb6b4c630783503d29da1834" },
                { "kk", "b2b049c87060225acc419faaf5a0030c2e278ec5ceda79afb09915b14fba0afd1064a70e9e5077c4490e5bf56d2242f354b710b9528411a551adbb4e744621d3" },
                { "km", "afc7481e88d307499dd6e098dabd604e3ca96a1ca45b4f4fd7cc56cc7a169378c8a440b2105117488a3af68657606643e97d80ba2c659f3d6f119af906a6fa0e" },
                { "kn", "504e38a8f5c89d5b59c3546d294aee1233156291531cb569aaeebd5bba4e7084cc445b65f2edb06754db864304e95ea983a92b624c296e565518efeb9f2de94b" },
                { "ko", "1fc223b1e748c67ab425376c0ec01abdee6588f649eac1c276b10b70931159fa85ae69101f68318c4de604ce3179a6bca5fb8b2674fb1d39fd2c2649165b57c7" },
                { "lij", "bfb9316941020d692f59fe490ea7cdbabfbcef0a6e2752197a039c3f2be9be51c09c53bcfd6f6c7ad5ec7f3b7795c6f63a950575eb42b44b3666ac45d3cc672b" },
                { "lt", "6046d11cc90d93db4a205664bb5771748882ea9f0fb74d734114043ae21a7cd4dff80141871bf3fac44da147e321b4e82d16f47c325022a0480171506f154af4" },
                { "lv", "6efcf2792d6a6575875d5bb883d4f7766e9293de56e9f7f4e66fa41db54259142cd0d5877f9afcc74c5be86c2f7906ce27ef21b8a2f1a3abeb4df5bd6ec1a730" },
                { "mk", "65738763fedee98a8d5f7735010798667a3faf74d5cbd818f4bde522ad18691c03980a52788897d0a14af7af8d99af57cf99012fe24a69797365c4fa0874583a" },
                { "mr", "9ac0422ae694e9dc8cad98d83b666f745ce2de50e6bc116dcbd77b88f5475bbef08814dbce75190c51ab43fa8e2e3b2078494e6c1fa989ddfc480f4dac30ad14" },
                { "ms", "9f906b3759af09365cb7bc81ad830032d516c0d7ae2ab0d3895709368e8d60769a3ac3f0096bfaecb3b488a756455e474484080e07448d044f3640e87091c2cc" },
                { "my", "b561fb5c306e4f156c827bbaf3de6bd88810955684bdb68bfda76ee8d159228eec64787b486d9d6c1e116efdfc43eecc553e36abb21792cc5bdbbb861a4e68b1" },
                { "nb-NO", "e30604fbcad6793402d1c831d85cc863ec9350bd9b3c77bf8fcadb44ae51cbd4d2aa5160c01e7d966fa7900824d4ff8c5da81a6222c91bb1ffc913eea4d1af2b" },
                { "ne-NP", "278c9722848825d51eaac1f3f62bcb38191eca3344de1bd5a92356df834c22fdf6ecdcc44966bbddd93289fb5725243cc7b1dbc0b107dd6a6698e39be4130608" },
                { "nl", "6733130ad7f479c9d911b73785cac3ba54f67ce30119a328628c8dc2c4d6f93f1c110d19563794c755d6a158f8270f45563f1c536b7d72853ec4d544e9922689" },
                { "nn-NO", "4a72eee926f48ade767698f208a530526a157b7f0a79fca471764ee9bd425044cc053c3f593afe20b3f4362de6d925806f3927fdcf825b0e3f3c00f0cea27a39" },
                { "oc", "bf6f5c308dc1cae28b40ded76a67a02b47ab2e1040276f4e9b8dfd525f5a9173b1f6b0926aa8f37ae9f83c6d9f611ea7436d5de04176a1cfa886c351255788f1" },
                { "pa-IN", "5a3c79299e47ba89dd6241ab37f2326f5005959e2858067d85a01f41f3e12a085c36d7481158c559bd913524355a7e53025e3891743b9d6056e5988be3d813d8" },
                { "pl", "d715cecc9ff0524504307915862debbd30becc2f5ff08e519bc79f88411bc80db23a3157570fdee064ea4f6ba3dcd641bc4943bf5d4de3f4b6135431c02e60a3" },
                { "pt-BR", "4f6e5adf1ad415c7e93acb1d01ae68006a121d0fd9143910cb1ee7d9233f9c86abf32f80fb7b29a931747d529c93828329c7ef43f7895c66b5414d72c7cf29d2" },
                { "pt-PT", "29cffdbd47453443a517307688b89b041fcdf6e27b14ad3d0edd554da014a4af6cc2c969fa1bac8410dcbc01e4510f7330da58804de30df166c26782847dddc4" },
                { "rm", "c5193a48e8360b1cee3db1d6b2f62ec6736f60f36247c32aafc2c20182a7514ec4dbfbe8735f848dd6eb35cb4502765898199270353447bb06653015b307bf57" },
                { "ro", "409dfedf1543c0f6d8ec4b3da2b060db9ef132e37c7efb391d9382d77327ecae0a7c442b149eefab655e7eb26a7b0968352403fff1383cf6f96ea4e9c60acd49" },
                { "ru", "297a5bdc8dfc3c86df746ca4d48ebe790c5adc4ed1f48d503a9f5b2feecfde6f5e2836c7be2cc0a7137235780bdcba1e483027860ae8d9e39f4417f4388baa99" },
                { "sc", "e95ea49641e17ec52ac768819286591674890a91dd2821443331c364f6642644b38145002e688a20b98692bc540c7aa6c1136822d44833e02c749aaca8e56d9e" },
                { "sco", "15a0bc56319f2fcfee6d54ad16f45bbca1adbb9fd426c13b4d4054675fa3f9069fc295bb01932d39791435c584be8a70416e784e41f8f158fd7cf2ee1377bbc0" },
                { "si", "098e7b41ec5de0aa345f76c33f54e8379cf1f5943b1b59bb678e0733f27e868d8a6f4f2ed9bb06d682fc2232fc5171bd89d2728e29ab9ed4f4f899b46ed5f409" },
                { "sk", "8911fdcfee348d3f270640c41dd46dde55ee07eb3c12366db571a71a898d92c96c501826d7ef20fac2df140475246499763acc3006731412cad5462d7309b99a" },
                { "sl", "775029644f11faf6cb9fe0b7f54026b70d7ce1a9c1fc9ce2ac7575753604791894e6560eba11aab57ace573f0039c482fca75c2798166450772b702d606816f5" },
                { "son", "415f004d2251ecbaabbc00d2b74587b64451c15f5271f9776a19eb08b31abae29ae7ba5a792b86206d0be8a3997313e6c571d29d16a4b31c5712f11e856868df" },
                { "sq", "76d3bf3033b79de2d0d0f97dc2a72cb8ab255e42ee8d5dea7be21d6af560307bb646f19bd11e417093cc5fe01b8a3fc6e68965498e5ec4201046101d03bceded" },
                { "sr", "5c4a45767ca73c5d0f9ace5e71bed5fbf1df19e01ef38d2e9f394074509b874f498d2ac2bb46e802123747e0af9685485b119c1fae49e098785630a899517c67" },
                { "sv-SE", "5af7fae60a7ad2f728f133351c8253c4c0207b4aa522f7a2f0b1fe3eea985850258fd914901f584ab95341bf540b3f01d863a848ec7181cba35b996f4cd0f487" },
                { "szl", "8dad157d13320ede4382bbd1edc1f833a62a7f2520f1e2d72cc7a2a57ade83443e957be8d47dd99d0cb855e3ab53f6da4c9c68c6b5f6756f152539a667496ed2" },
                { "ta", "22431d7309f5482aded2f8748a6f24e976b5d4878a7da3e3e69546db57f2a1ea105640cdaa21b0be7e4d8526c4a61f2583fa08a8f0afcfcc1a79cf228a082964" },
                { "te", "01846360c9f59e961e6cf449eb210afbe678f89432acb01ba8ed845ecea7455a5fafd132da549835e06af7b8d42498e1ab21a8d3e159ab6bed648d200a2f8ec4" },
                { "tg", "5eeee1b1dd2b283d6eec724c8ef6f50e0dfd34fbc339f957bf4fb3a28fca0cf5174c26302d9c11ade61aea70689306b8e1a5df6dbaf2544ac8742221f9722b99" },
                { "th", "b0fd8cf193f3b50c7a92feed5c05d81f70406b01ec517c0238fb408d22a7936a491cb0962fbff572b924328e9dafe9e60190299a9ec1df60df4944f18f815751" },
                { "tl", "9e141e6bf5e9b465b9f5a82ce24426a8a8d8abb042b75cdf41bb37f7925514f5fe36544c9699008f716cbfdfad7056f10e4b0af941663d683912493601a2dfe2" },
                { "tr", "b505235144fb67a76c01755a519e6cb3d85484cb535db3ade4f17849637c2f7a71d956b45e3f1e560038823b75ae81c250d69e3ba0ff7646dbeaf4eec89ad2bf" },
                { "trs", "5ed64cbe27dad29a1cf0cfbde99305952feb04dd18723d6522db6a08091c1fc6fe2f968e93d91f8e92da56876df6e1fb7ac82e088eafa8f316c984dcf6caf922" },
                { "uk", "75ff95bdee6394c2980ddb314d0105e724d911e439c81ecb48d5e042953a062d30055bd7aaf80a10059c184215de6cddca4a214c66bf23736369fd6e924710c8" },
                { "ur", "747b3d6a3e9c13156b255dc7b1140491ffba9aca20b365211d547957cdcfc1320b1cf55487e8482333e0bace08727bc46fd2434449957ba13de50cb24e9947a7" },
                { "uz", "b1236a24e3f937b25dce9a2daa47ddd45bd3a14e1c7663bd23b50946d638093cdc97ff256fe33cf32b92de5a10f590f55e23ae872cc0389940891c52e0d7a274" },
                { "vi", "90682ce912d3f697928ce4a53045f450cfa0ced90d2e47bcc6467423d4f1e54d98c09d06cc1003cc3cfc389897e4a245ebfbcffe2190147dedcc491011f798b2" },
                { "xh", "ed7b93042ba17c233aca2db315cbd718a6ee9e515216524b7ab11177531e798a76936eebd8b8fbbab068053e32bceac8de3d9efe928e83fd925ff9168049948e" },
                { "zh-CN", "6304ea0dc06cbd93b6abb8f4234239852bf715ff40bbefd2f42df1e18d133f2adfb74a21c4d94a08c8275420960520277bf4c401a5e017526bc2cc210415a697" },
                { "zh-TW", "96bb82cd76ac863f93db746c1dc0503e11c0189e94123caabc1553b514f8a9d5865589e8369c6ecba5d7f58d2793b07f91557f6bd65c76aac820c569716b55ad" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string knownVersion = "115.3.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
