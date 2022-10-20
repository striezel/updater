﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


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
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/106.0.1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "781e04d4ce1c4debef2348c6432f425af822eb9f318a077d5759c5dd2a00f32452a00dd2e421bf6086e8e7cf24a4f87143042dd6241f668f0b6d4426df81216d" },
                { "af", "40c90f19640e3a6e3db12998e3dff751512d75d911fbf40fdf7b0c96880975badc1e4b4bce4cdb75f1b412ac85daee6f417ba69599b33226584154b548d40109" },
                { "an", "d2ca5fd7f79959648b63330930d7748e087c8680e92fb211625fee8a54b8d8074b637ebd1a952254e4a1448a3d2202a3589066c5aea6ae173ae797c709384e06" },
                { "ar", "953c912e7f2bb6e58ac13383a40b2644c68413add42f94d42e28ed2a41cef2617eb75e92992f42f58fc86fac6d7eb0212ee28095761a610aa868c957a8f44175" },
                { "ast", "8fd1441a2864587d98c20220fad0fd1498cb79e6e574aa9fe286c113528dd80e45d03ec9b0f1aa5f5f60055135fc5650df97403fb5d845ff566099502f15f37b" },
                { "az", "5e7938c0ec46cc074dca26bd028f5dd4e716e431f13b8dd520c1adf9808800d64e08ea4f6ecc223d42187714f8e95bf9fb8bce375caf71dc975c983f287ba5ae" },
                { "be", "b28a6a0b77ad76be822a73fdb8f87147fe5c4e498ec11d6c1fd22afdde87e49f6cd180d13e5d2f2c62ce7557f8836840e016c746389ad8562fc348d8bf15f4dd" },
                { "bg", "a9f6492afb65f0e401d75da6e7567f64160aa2e6e3b8fe01fe54ffb7326e43f20167ed420d9c59ae157ef90e55a64c5c79d38fc5b164dd4014269facf0be55bd" },
                { "bn", "b75ffb682e0ffdac59f0f340fa73944011a949cfeae8ff6c845c45a7ab2339b170f85b79d9b063668a5b495f9ebabf18538cb59167744a7b763e346ed34bba48" },
                { "br", "af3c49f702497c6c92401d7027d8a3a4c82c352bc3e653adc1150f899a24b58681f3a2d08d50624abb3ae055977385d2309285dd3c12776948cfdbf51a1d7771" },
                { "bs", "902541f15a1cc9dce67e05d01bc80de8ceb56b84c2a009f550da77385fae34d8945514baecc452c0ee9365983b44a349d8e5f926d20e48673b1c138405d171f6" },
                { "ca", "6696fcb170bd571f562d7ded47da5c1635247f333708f7469e43d6de0c095162ad281271e7a60db9ecf42f5d1557baa04d088d4c9b5ee580f17636f74a8d4cff" },
                { "cak", "b45de7599e54b4789b7084f012c458f4538e9031a52e0f7d2cd22bba61a36f0d8285d92b2b0555118b6b9cd517161baaf8331cf2790b22897417f71881d66a1d" },
                { "cs", "930f8014f8f21fe7d5e6f12bab5a3837d2472043dede3757576fbfef0fb06666f66fbe3a3d2312a122988c2e6806418541fcefada79675141b38935a4e08134b" },
                { "cy", "e9f9ff52197de61d055e60eb5faa078e0ae54f6589980bf0e6ec29f3b45c684277a47f4ad468b7466cd81192839a425279137490d0373bd79fee5a1bf90efe23" },
                { "da", "13eba0f7b7752662bd28e138b5940be0fa27cce7c8eabaab261cc55bfef42f3457a34f02c8c76d9fbeac7f8da53522de188907455c9b65cdd9800d1761809701" },
                { "de", "f346af6d726bbed61768538066691ec2ec007a5f55fc53aee584e3c5748d8e907fbe0c27a8de625ac33922fdc3b1cb211b5d958924be1d3d2b1158b93556ecb2" },
                { "dsb", "e8f4d9d491700c129d6d2bff31cc017d74127861feff228b8429fb53e580cf0886d8c95e53efe5105ba67b5c425f18d8fa8a927b8ad1e6e12d597ccbcde5de9c" },
                { "el", "c158fee08abe15539e1ba54b8809b57e7adf68b7668c4f189e70e352e1a709b3412fd32741c0045e965c9764ead2b28216b3175f5b0852d91d5b2c054a4379e5" },
                { "en-CA", "693936905662bff2817153c7164c4bbe6a7e84b27c7b3a2299117610d523945c1c297735e3c7bbd476b652e5d9469109e3bf9a13f6b4494c169d55ea4ccb61b7" },
                { "en-GB", "e53ffc992d1040c11fe610c8cfbc6bf3434e4c652648c237cb35dc7910672dad710dacf1df68179ba2ec17114259e757d45d21c0d69807fc48742692f00ed540" },
                { "en-US", "7c3aa603da3055ec15b143ba94a20c323e04cb28c513fe8f56102236564dd0a6b4d0258213313e9fc2a24bf87615e786ca9d9b657ecbdcc7f736b2a19ff33c1f" },
                { "eo", "976214f8e696050367909211768b83859021620abcad83732d07ac498625c3712f8e6b46a39b362ea817cca2814e7145dd1eef753b0a2abbd8740d07d1fd3b09" },
                { "es-AR", "12f8b3c3f0cdc5d0ade1e8f0d260b0c63bc689e294388555e205e79b8b94dae09d71797f62f4c3822d64504f04c4180c39aa81c6672e5e35488a0366d2e8affd" },
                { "es-CL", "32728b95f5ec8fef1267e23163bda94d583e74cf3777395f73328605dfdfca5344ae1484033707409b35326a323fb59c62d15c89fc8aaa1913cc5182dedfb2e6" },
                { "es-ES", "0e8529daf5b81529a89f69664b9c12f4d45b237bd91dacfe9da1aba53545d18b1fd04abd24dba5745c576257957c9214ef76f28ccd4d30133fc756780275adc2" },
                { "es-MX", "4d79f8556d2c8e69e43bbc14bc3f3b741552f1fc5a4f2db120d5137d79a6467b4eb77ed8b8a622555b6705c31294941b08880ddfbb7aa8ebcb46cf809f854db5" },
                { "et", "31011973c297dd041ad056c19780532a4cd03b6429b08cb40667fcbd87d8617fd66b8db90559d8098b55116e4cfa152c56d929031517342ff701316abd8b4aa0" },
                { "eu", "b08b564f628adad4000fe0af7ef283a9770b0e940677345eae4f22175ccd8320943f26a74681dc9ca8f3d470a447b44fbb4aa2cc248d4d4805f51b4c12a422a2" },
                { "fa", "c8669616399a5d4dfab453fe32f6236c6fc6f96928f4f133e6d7fa9c7e77fcf6c78bfee599c5d7159263d24b68eb74da1c865eef4fbd6e44482ebb924bca1ca9" },
                { "ff", "3db451266f9d4d14195813bf64d3958a33cfa90d5cf7429063b1342318344e95033a58a0bd236a7fe89656059696daba56e9510adb6c5992307341f4d945ad48" },
                { "fi", "d631beb6f25f036b079c77ed73635b57efda5d0fe7f3c9b2d31d195bdb35abda41a80e83691017437faabaa8409fa24bc33374c6d93231cd5873f89c8d1bf563" },
                { "fr", "90f244536039e2337d0c85c6cfd9f13405daee3e1bac2f057cf75241f61d3213562bd276a55108480e55f61584d988591edcf47a3a5f48971fb93594b93efda1" },
                { "fy-NL", "87babb901c4047742c34cbfbadba05b791e4392c7777d7104408a060fbf6557d9c0e8ca8631d6aaadf565734691e9c529b73d681aed74fbce8865758da4059db" },
                { "ga-IE", "4c8759f5b0ccd9c5f8cd5275a922b2098e99632ebde8af1da3aebcab734c3a2e6ff69a7be7e437ab11fc1f3a62a7f92b8ec1e2e7390291d8bef650ef32b2a1be" },
                { "gd", "65323cb8bb8491c34f7e736197133961f23cfc41da6f79263512e8409f56b78a8b4b17bbff76c3d307516660f23f00ae25c1b7c94976960421daec00a89bc649" },
                { "gl", "1f60e6562b91a8502fec70539f9acc2414dae8807c05427766625646c204a5f8335de9242c023a6e5be80cbfef39b9ca53bc1ca612b117d58f127e4da48d97a7" },
                { "gn", "29b05510a881b8018fc2c3abf9291ae843414abf828199e52f50a8b362f06b111c8682ceca1b45a939563acd3f92356bba1598b314d2942ecaf061d241135d7f" },
                { "gu-IN", "3cf1f06e81364c1deba5c28957a1fca7ef8fbf763f09713c4ac49c98398beda3b6eb42226e47eec4d6c15bb55f5e7d973b5540639ad7c06750189a37ff2d328b" },
                { "he", "635197fd3d388fc29711a0de277005a522b36d4f187ce3b8b6ebb2f2356ded63cad6dfdd2ef373886cf4bcc01e2de8db729d58bcd1672e110a78007288a4b228" },
                { "hi-IN", "56d04457af9743aff29008f211f80cb9a63f29146e5fd2cfe8677837d588a911417ce40061f0bffd5557e4f50b6675518c6835be45251f3b35ad8bca0538cc64" },
                { "hr", "9cbde6d2d61a33267c3da1f72a171a47a8a3cf45b75016e7b2da4f57b50be4dc00e443341ac078a2611237329cc23cebbe0bb523338b4f19cb207dfd53b2ba29" },
                { "hsb", "31df6ae35772524c05af4841927e33a74aefe616a6711cd1fce4b4b0e4c52917000d959d5846241506a4621c694f916bb54a772f4be2b54b107634024c23226c" },
                { "hu", "d3166026c497c4563c63183440dd9193f25e082fe3234f2aa7e81de3a254fdf46b638bef81607d76c6fab1d173059cf79aa74d318f7590ad474fe64680c35bf0" },
                { "hy-AM", "d20aa4deef3b62f603a53b4e3dfeeb9f62972031c397929253de1564077b34ed9f04abc33172c93935ba71664e69a26e13d406b4d57c01214087275cdc016070" },
                { "ia", "9c85deb4a896e9b05e9dc0716503ca183d2b71a875c0141a68b4c47d697033f7bdb20c5f075ac0c31c90efe436af83e610a5074be9c07ed5176193d9fbbe1be2" },
                { "id", "e0077771f86a360f6284e4bcdfdff25e63b7fc27fe033cf42327dfdcb0ea37ed5a075b6973e4acc8b0eb27394da0ed8ac74e13eedfe0184dd1aa325d447cac6c" },
                { "is", "056f329fdfe1bbd01ce9e4852779afe227471ad06d7f990aa5bf29bf3e7e20205827442cb0acc66f74c85943f273a1fa321d7f599438cd156526f5653aea2d05" },
                { "it", "8be3c60991251be477a6c98df85cf3470fdc43f46c8e7452faadfd416275f555d63fda0d261f4560da5727749e58a6aeaf3ae9bef2e2bfd3ae960b4d087c0b88" },
                { "ja", "b37c016690c387e2cb890da995e2e05988c0b5539b6131bb6040d2607e572d925e7b60204c4912285165fbf3dc423147cea5e6b2f1b8652c4e54d2255b10a941" },
                { "ka", "07a582fd6d1c079a76525a0e1e29b35eea6fbbe20111ac046ea263a059b2f9066bbe97199c5a8ad7df3ddd197f37750adb63fc1c72afbea1164a97306110ff8d" },
                { "kab", "4bfa1011b5515c275df433025ccaa488e8a69e825a49f45f665fa406370044d3a3bb3b7851aafa290573ac832ce0d4d7cc07653a87ed7f7413848cb36ed2c7c0" },
                { "kk", "90625f8af3267645bf370e7de3d5dc75a3e78c85ed964af4dcf328280d9160d8ab5d7535998848bacd1afc0d14467a0481eba52046191304fc0e4d33e6f38f97" },
                { "km", "d6629941ed561690570a49ee6bfde5f07a1228acf34eb06ce4d14ad8c071530556e26e199f4d66b61f6c291ef827f3b73f6dedc61a0c52dfcc1cebb8120e0a49" },
                { "kn", "ee6a1115d0ae856420884f494b11a943a523a54143e2bcd7c60fa471437d61ecfa3369db288e4af7db422c1d3752b113c57673fd241eb11f2d2b8e3858ffda4f" },
                { "ko", "f90e7e9d3fd19c353784b929b2c192c3c0d84109b17660200a39c4f2256a11a24b732ac9c0c4a141941b9dc2fbd8fd760504709e70eb65f08e9ca550ff07b350" },
                { "lij", "23eb57f3da49c3b29cd87061dd5b8fd5c70dff25d060da72f01d9a6b07f8cc9b54bfc613c94db0404a6bd11a840e71f26034ef46caf66bb5336cab6f1c005329" },
                { "lt", "342292ddd0e8854192b588e0b7c68ca4755e0bd1bc2e1982182a9a65bcb15bf2565ad88ea856b558cb3f8d38d8398eef08662c6307bce8f575b5e0d51235c005" },
                { "lv", "51cb465ea0d2db71c2488abf80641a9a36e3d64dca75de3cbd75a5adfedd830e76b5087609a62fe1c59a97c1f7e668860e05e8617166e5da2ce19dadc428762f" },
                { "mk", "effdb57a3ce8b5a5195dbacc97f7b9af16048b036e33109951b73cb2156afaf552ee3b96cf8bcf47486d1ce5653f6bc2120f5c29592f2e7297b97b710d9a2d49" },
                { "mr", "f28f51f00ecf3605af959c6f7c03c8b27cb6b8e2913b5e690f10a319aad282afa7d4164fefb16a8ccc9b9e47961265edd92d0dba35417190c403200e44d80559" },
                { "ms", "412da0fff167512ec1c4988139cbb5748fc9008cdb53ed72048b5be387a137fe5477d4070e1a91ab8e61862009362456d5b90f4aed4b4954bf8f2e85e3cb66ab" },
                { "my", "0764fb257ac9b52b59c79106cd7ecaa7e54da0f1e54a29b0e72467c92dd296f94c9efeb48ea3f4ebe3e52b7ba7f43659fd8ad3a87fa106b0719bda3d9d57d928" },
                { "nb-NO", "030142cc03534a8345a0906b4c6aae13a128761f3ca3a73a379995809671c2aa79ecd8eefd771ed72cd0a3423aa49c7a397ec6d7a5094364324b219b431fc1c3" },
                { "ne-NP", "0d43deb7d2dc2147dea3ebee41c65c2bdf153e090d43bdf5e5a562e7954f3c5c3dbc1bdf1a1a5a1370d92aaba0a0058995d812957a0e1f7230426868ccdb12d8" },
                { "nl", "88e0fd0a53a5e5a6390117061970c5bf0e3923ccb3541d8a681636fb22b4c354b535071904667e7fe09cd406e7be8ec32d2a380cc71c5c0528b020a83d9c8f90" },
                { "nn-NO", "76facf2a75e411e3cab5cac0b9b2d3abe613cad9d1b4ad02a2e30bda7d9c39af3d45dac4970e0da1474575c686c4ba11ff7f5592355c3fcf42443879812a811d" },
                { "oc", "7dcd5e4c0e119cdd423541e2338a34c557fa850ae5da9f46293c3d0cbeee2dcbc6c8a71e7587bd2f4ec8d6f7c4757b8adf129420f3d89a4680dbd0e91574a7c4" },
                { "pa-IN", "f040a2dec1222b38185908f5db94ceaf973bca1557778399d3cb0b3ecc19deb7ba486c913955ba2318fd3e82d617344fcdd3d9e7bc922d3a8b1aa6616106f34d" },
                { "pl", "a8d8064294c334a3143151914901352b3be26827e2f65f34815b9dd61c75623f037df62c0f469702b84f203990e70f3529c00d357f4f41f9e1e94e9f23764cd4" },
                { "pt-BR", "a504611091c7adb8a2f169f4627887fa8e8243fdb3a2e2ff2551e6d9b6368f6bc9981176b7039eb74de03d552f4a844dd871c8a4c08145aa22c1259b8d2f0359" },
                { "pt-PT", "59b8d0f66e04d67309d04a8ce51aa248f6feef01359bb52bc26539c927e9154b21abca6a024c7cdc3defc198e627fa14eafded9b1f0e12eef6f917b402fa87e6" },
                { "rm", "00ef738a2dcbe55909719d1599e098a043ef7a8b5633b3bd62e0608102d6dbea884c457e35dac4d56a5ceeb5430d99a68de776c83be7f589b46eeb7f2148502f" },
                { "ro", "209f3ca0eca9fb0785e2e72050481208a49bfc9b697edd5f685616f9842103eaab6c5f4a4d356917d0daa11e0a9b2af9a6a6793a82dd8844467099366764f62b" },
                { "ru", "54694e84e428c50b0a4587abf1e29bb4cdc699e86b7254d8bd100f8d0b24185867df3d6c0ef9e6628ac02d93e1938efbffaa0bd4fdd2c4288bd4cd8d7317c366" },
                { "sco", "975b26dcb6cf4bb4e06168c0cbf035a81acaeae688a936c0dd9c640fc5fa2ba516d67d1da27760b40069d6a8f03468f270a8f411b0678574bb750b7e11a9a7f6" },
                { "si", "8bbc82acb2c6cea81355852eee947c3bdf2f6bd16a5aebc65cfa99160bf0ceed03b45dd364dece90cfdc146933d0ba038a5c9911c917c9f1d66959c0cc555247" },
                { "sk", "de87662ad39080db7a043e885bc7b2b67d4a4fc8b70d5fc6207b552e35f9aeffe83b5f4292126e6e3add35ff0baaf5947b4f844be8c1e2e7ea635809548bcb12" },
                { "sl", "eae073be686c2b6894e298d09ba1b6801b5c6d561ffdc27e2badb885a8799dd79ef09eb14b70a72db19845ea3ebfb55bee70d92dbfb164e93ca54c0dc361dbdf" },
                { "son", "71978d3b6e01e785dd6607b230be7f8b82e1c82c932c2463f28adfe011f38d6102ea3f1d4478d7f5c8808697b3edb36bba9823d22071417ba6c2990c7499a9fe" },
                { "sq", "58250290e2d01cad18a1301ef5bc399878ad1ef8a7796f1d5c78db98e5df9297e630d0a2d9d64cb047192688492eedb74a16aa0db727cd173ab4be80a58767c1" },
                { "sr", "4e34ca06e756640110308f96a25db2ef3dbe8c2344f2112d0e1cdfa08fc7c636ee112e29a7b4f456547925e774466bd09ead57ffbd6b354825f0c2452a917fb3" },
                { "sv-SE", "2f8411530c265a69b78d8b739f01ce3b131222eed1afaff8187e588a8f0428d4a5fad66f4c32e59fe106f0c3864daf6b9bd03cd19f23793d08ac649239f7ef51" },
                { "szl", "d33b153f0df35f6abf7a2fc253e9ce2c5b2e981224c2e89af6811814d87fd5160af4d0163b34721490860c19e25326ffa59c255449baaba6dfca3041d9e2a6b1" },
                { "ta", "7b08b9ed4937bc3e86c67fc29dd8ede101bcb792887a2cb6f64c6f72b515f0dbb0f3ade0533457dba7099ebb776796ff7d9b27d508c55b105691e2a31cc54d0c" },
                { "te", "613d1a76c78dfa7894bf7e287c68e115a0758bb5364dd6769b692e855ca513b50430802177db59bbbe52e47634fabdf95aa97a49e1cb4531e82fb9355687c9cc" },
                { "th", "ec4effff31c4c524399928ef3a93a31d1b130b80dd6da48c2c24963cf0c497b1e26b4e7638bd48b8839721146331d9120dda1e0de2747a54e8d151422636ab6a" },
                { "tl", "32d36a20749e0f5e9d44d659c4128ad8ec6c80deafbb772e6f59731657fa9c2bc0a807c93143da2142b714e0360edeb25c21209523e9d3adb6eae70e84e620c7" },
                { "tr", "d201afd914e166d86580789b5650bc786bf7a0c266333b1d34ee3e499c9f4482bd30227927053b854f99b7559216f8072dc841b9770cd74f87fcf4bbb60d0270" },
                { "trs", "25625f328aaf19630cd1972d504a6e6969f31682c69b0d955bcde8b9479254b2334c77e40eb3b4184af9a2ca6a819b6f18a0bfac65ecd3fd9dc55cf4d006ff1e" },
                { "uk", "03fedef2f538ea7e624248b312bb456423b17bb352228981fae092ad9b5f5274dc36179115ba19a30983625c8c8740ac6a876cd0fa5e50fe0d4e2b0607047af4" },
                { "ur", "9ea3a2107fcea08c1b8fe4ea6103ef5b9652b2d3d40498a09dfd1097ba3792d2a198860da2a447e551df4829a8a58fe943786d36059758f29c9fd537135c599f" },
                { "uz", "1f83eefb4fa8186acce055a9f292292d64f85fae6b7a303c1c8e015adb5442aaad193180d941405887e70db7408ef388b88a5d34fa7d10d439d720762d205484" },
                { "vi", "390a85cce1df129323006616bff2d4726784a808836e87cc6eb4b3c6b79e5a153fcb46d62ad0a826c83f099e8fa5a9d883f5d2bd5b903e727c047d7af34a9ca7" },
                { "xh", "03479f9e80400323ba75f6a03917e179bf10518f7d6b5720745e798b9cf880899a50cd75882e2d10b48dc3f020187a9acfecfa3c551078b9d2d084e54214df9b" },
                { "zh-CN", "c790744073f442d1d66654e90b626dbb14842e62927f10918839b5a3e665bbbd57a229aca45e7c17669ef132d0314b47e33565b4fb71818333717da50ef816fd" },
                { "zh-TW", "e98df53ffba16410ef0343ff928ff31e76006cc0c276067ab2468690f3619593c50eaf98463a477bf84df782314e8965c56e0c37d335a0166b4bfdb330b3e4c4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/106.0.1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "6c36473687b28b0904c48c2c33544bce4de5c878657500311cccb536c8f77afcdb960193942669e364df5555349dbc3de925b6cbff1307b72edb309bafba6f84" },
                { "af", "2b985ada3d04c69a73b6a5327725aed8c6de2ac770cf9c489411812de584ce1ab657bd76305aef8443110e35578ac0d4a4be51910c20a3b4a920ebf330b218d2" },
                { "an", "b771ef0be564f9b7cc54bd7432865bd6092fb0ec71af02161ccdb86882656df51955eb844c03285b343fda418efe2ca33aa5fcf5d183f028488c6bd4ec372af6" },
                { "ar", "3b8991378ea9b8acbe5d7c6d4f1c6145b5bee4f0b6f9a32eaee1981a4809357f4968f2ef782d902bae972f04c7936e06eef70dbde289bae7f0679ffe10222bde" },
                { "ast", "bde8fec6aef2dff71034c06c02f76bb338b182761d26ba9e3dbdb791c7dc1325892a9c98a3d3fddea52a80c097f3e9856bfb984f85b38be1ecf499ae70eed640" },
                { "az", "cae4117815d9e22854284a0a3e75381a0fa0c475cda53782f65e7a7df18da3ec55dd3bcd681d5d403a6700d5ee2cb6f20da6bd946124dfc86ccb584852e23767" },
                { "be", "7b08ce2425f3f550fa56d46546f4c56a3790671fc0d4e5a977f6a4420e651fa55d3a66271399fd2f3a3e85b019f3c5a8738a0c1cf6f52a7379c8587fefe759f2" },
                { "bg", "84b4057b46ada84350d00ee7714332759e7bf2ae09d32cdb932dc616cdddf215279ccea7551ce5c364688868a17251654c9a33bf89419dc3fa972c54ed8cb6cd" },
                { "bn", "6b015d605ee7881c66695d5968b4a886bbf1d2334aa1b547b272938419b879ccf6676ca4434d818115f736ad9adbeac3cd0569026407e363904d2b7cd4ac9f32" },
                { "br", "b8d266595285afdfd8a0b2425fd8ec587f2208a30a80aadf5adc9377518498159fcc721aefea65b11fb81b4b72db99572a7d485013479bc8cd5082ba933bdf3b" },
                { "bs", "b97cef0dbbabfc7600b5cfe073e6a1337ef485267d479a757006340aa9ff0a8f3d17f9f058e566df5a05a371923d57c130b265d42c861a10f3e002a0ed093c51" },
                { "ca", "974d627e6b5fbedb9269a7554cad0298fb03f92ef02c354b72d79f0024e25861fa5cdecc0de18e429ca2a0272114a1d74c69a3496fc5f5e502bca21379593b50" },
                { "cak", "ac9961bf33f4c76dd23739edfe560fa01da5f6ba732302f7bf6092a86c85d4a1037be37cbaae6d5d550211efbbfa8a9ace3cb0cb1e99bc0e55c532d0f82f2510" },
                { "cs", "cee9084898e621a49bd9e54f92456d0860d25e5d2629d2c2dcade72d29290ec9a3e9c2cd802210e4f2d0b0efdd7e98621c5380cdf0e4edd4c4007d7bdd6f74fd" },
                { "cy", "925cb4aad949922d68f6f8fbe3bb865612004e7c6ac8e0935036869992d6e09e0139e0b13e1dbcc5e94a6f11f65f9975483e35638b0cc90c24f740c5061ab74d" },
                { "da", "7f34c10db2da64fbcc921103d6b6ebd1629b6bd54ea4bec649665800f7f964b513680e4618a041eecbd7a020f3ca0422c8932170a70dd9c112c8c4e64e0a37a7" },
                { "de", "c8493d4a8ed7f58f60638eebb14b629ce1b7878f562e113da5dfb04350ed2a43dcaa557af2899040446bc91b3c0b6243ce76f0698d24643f5eeb1e895a3bc484" },
                { "dsb", "009f52681e3547d2543dd9dbce51b1d11e4da855f13629e9315ae3fceec85a1a9d96ffcd4e3f6a2c54fff72c701bc742444c819a3dd03b1e3993a8172fc44dcd" },
                { "el", "50c7995d596568044bc916b405d194d145d270a3236622b7654b6578e66d6710580fd6654724b65b8f690a918494daa07833120e3fa04f61a85f8022b48a1062" },
                { "en-CA", "cbd3770650c5b6ac3402bc8a8f63788fdc9a7524ae863a0b84e8d99d163bfceb3badefcad7475b1e94534912fbb6b6ee1213ef53561a732d4c6bdfbed1a21381" },
                { "en-GB", "b84282ca4ea05cb31cb1592505466cdf4e2534a8a3d5878dc1a174204cc41df7ef48e56e5e885b1feddb66190adbdddce3f2a93da46603c82a088d0aed71445d" },
                { "en-US", "558812e1405d9f4f746affe4f9fef55af530b96771fe66b9ca45248c3f5de0939884d745ea4171bba34e50f208da9b913d4a6545e1495a2be5c3af4caf4a754f" },
                { "eo", "27d56fbf1a5fbd76908c56ecb89d80c696671b3e83788b4b891bc2da176328ce61fbf585bb30f7a68ec5382752b98b413121fb6e61344d3531d18045670dc2cb" },
                { "es-AR", "aa3435c45ae105608ac100dba4a1de5902ce4fb9069e97e41976864e9e6786b777b970e0ea23d56aae5b2db773ac9839407435eaf1de35c8e803a2dd97c3f8f0" },
                { "es-CL", "4f8e23f6fa53a989969ab58f5b1ac23e7a5fd40991365e319f6ede13afa8e82756560bf8b017739eb8dc8d81af8a6bb9dcee0adac63340b59ac3394f3f7ec1e0" },
                { "es-ES", "f81715a44c9cc87896ee047f96c01e7558477eb2825557763f3fb70e0960ed8ca776943bb5e7caf3c4f5de4c1f7365d98d685c9638d2277210afd0071160243b" },
                { "es-MX", "ffbd49a2fd2651c3dd2c0f1a2fb181a2efff8df3bbb93a45a159d7df4b80dbec5acac9401a43df2f10c847a9ca2fee935b346a1684d1724157cb172cac237ffb" },
                { "et", "1913a0eb7114b08d9a18b11a69749dac4672ecd5bc95bb0b1fdf8b43ebba84615372e963bd522c6f881f3af3aaaf8bd1c3a80d726c2bd002191774281ad752d3" },
                { "eu", "0651a3f94d6e332cded5ec5aea97b7c5845983054e5e3a2beb6bbf055b4d0d6bf7a5a833736ca7a26dc3032c0d8d72a984cf04bdb960bf4643a1e9a3bf8a5ab9" },
                { "fa", "dbc2c6333b818f2e3194764a719161e9180b79cc565a04402956291c08b78446e044a291d453428c5911d35d37474b4f5be3b46ec74d00315c5ca33b7f65ae73" },
                { "ff", "f0c96c2b60cdc0b8e29b059ed868798a9555f8b97d73319ee87b6cb9d5a0c344a5fdf2b2acbc3771039239d36b897adb1d2400becb0fd5554f46e3a4fd791d61" },
                { "fi", "ae204a363212cf9d4a0daed6358fa08baf4338564264a701c64095bf0f652feabd3290440d05b9a0f27a7597ae9315bdfd9ed57bdaa0d1e8650c795ea3a997cc" },
                { "fr", "aca49b267f1c247277a75bea551f74a183cc2e71f42d89d6d43bf9d9d4f0fa39ec0519d51b3e270d8f16151c308310454795f8529e570e3f1bbcf7942d2c6582" },
                { "fy-NL", "13c7db6207f89d6a1916cbe04e000f60936a395f16411dc07c3fd702a9c98b0dada11ee9ec192091134accaecabe3d117d1b8f65be2fb02e771c51de5e671243" },
                { "ga-IE", "1b0a69c88a998d92272f8fa7d9ace43e9fbb09218c92d3d1aba9e157d5ef7635e454a8cc71e9050a2485ae6b48bbd4a9d3b7e44cf79472b0ceec7afd19469dd0" },
                { "gd", "3d2930c357f50088a1fe05dfce5a7f56379c029ef45fbae4ac98340a8f8d8aedd0ca500116c870e635ebe37b1151c64ea677c1b4ebd3b2ea2d9ae3facff1f4a8" },
                { "gl", "281bec720c7e684d6367625928bedbd487efebec30a7971ddc7ba77b076c99064df990cfa30147cc58d0bd0afeccd970c936df7c46cbe6204ba4c04b0a2a498b" },
                { "gn", "3fe0200841909127100cc91710435e3bb92473a21c1e2f5ab7d6b57733f5d0999c03b9ee9d2a59e77af61fd378f142f46731d79a9406fbe743c4b83c94ba8d68" },
                { "gu-IN", "b6a7faf5d358ea00d42a859f56fc4f9dbab5d948226feb3085085d4e998f766d14341e7e8ceeaad04091b490e6bf88ef1c1c0e9e8bb5be27ffc644c6db4a4793" },
                { "he", "8e9a0e8c463cf83f1f9e920b4bd869d6a8450edf723e8597f61df781334560b0c14b414b9ffb3b252bd0352e7e4a6f2b3f5769b438dfb0ea7136004fdf4b094b" },
                { "hi-IN", "526806e3ab26518bdbb0585c4974072bafb9a215b57265767ecf5d49323010b9182b8bf1191e8686d1c507463682aa9cba20c42126845e07717a77428ffa0f05" },
                { "hr", "f86ae50d5f7ac80478c2d167373c1d22a739717ec160d9bc2460dfa080e304f72f5dcfec95bdb67fdce4f7c29bfe39ccd9c89a53e689dacdf5d2f57f20970ce9" },
                { "hsb", "e5cc1d10ee29e40c68de81ec0d8cdd88d7f74b042c38c6f6be4861b0b4e8605ebf00cdcfd80488093ffe7fae5d9d4d99992cdc3ddf6000f49877319eef5fcf67" },
                { "hu", "a113283af49073d699c0bbefbac810c1fb6d565acd663f490f644f7eb4598752aeb57c0300890f1afbc34629ea3f2738dc853dbf7f57c48335b63ac529205b43" },
                { "hy-AM", "4d5c4f3c3d9b473765a53d73ec681db06065d030568ecd7bde43ae8ecea2c7596ab5c934373600af8256bc624f500631ac7ea70ee462ed5573aa984ebe52f42a" },
                { "ia", "c4ce9b65a4d171314d519d673ed57e3b9d195f8de2cfdcaa654f44a2c25d17dc2fc0157140c5c5553181c8e1d31c84381b943b6179524a6ca64461ecab00e115" },
                { "id", "b4f7e287ed2f49457d1993a014322f90897b2d9ba9e5047ec7a9de058db3d81d298eb51f875dbc08cf3e74a6d7aedab5cdd8067a2c2b0631c00932ca9215b529" },
                { "is", "6a0969a9fa9100845f535d884128e13d9502866010c4ded00301f8fd6932989a455bd7b30fc5ebcd1e54ef53a3207d0376485fb1359f840127de64230efc8a78" },
                { "it", "586a0d994c5880f4a291a86ee686b4d112bd590daa29609b21a0400c3d23661c0862b90ebae139ccddfe3adcdcaac06aad2f9b961f99d75d893dccac396bbc82" },
                { "ja", "9adaff78edfd9484bcf454150cd3cb99d63709cc5144439a497d1a3596a6c30f97a8e5f892598d0951167d1ee3a92a681bbf7b312d79619113ac2df801965724" },
                { "ka", "11805467b8fe848d2f5eaa25aa1baf4efa07957a57eca4635f9a72b8b5c550dcc8caf71ca3151dab665631b9e21ba1d2ea1f500d0577dff39daffe5533f1127b" },
                { "kab", "0e321245e71937c3010369c50687f59288856f165ae88d9e198c7dc638ab3ef70a854c39e247833820e8e5c7c7f24fc0711878b629f31a8bd807146b72924d30" },
                { "kk", "33af29eab15665b450901b823ccc47108d5e4e6cf1c652dc1d4ea583271eb12d3cc08aa46e8a54eaa01cec7337c56db8ec59fc695d10ba1c879a1597b91e1b9b" },
                { "km", "c0a54d21914ef18168e7f8fb22757167a0aa752bba2e886e9700416d7178a11814a0992b5316504c4b306dcc22496b21aebf8f5323c6d9b637108e8344a2ad19" },
                { "kn", "3d8bd6c6b2a6fdd6b4068edc66840d98f0a04fd8e770edcd80a8fdc6c3753f6a667f78e05d2e7051b3d919015a68c1bb79fa9cd495680032618d45fa7ef75ddc" },
                { "ko", "d495215bd809034d724c67a309cc515526392849232bf9f137d1fa61404c113418e9b7d5f4df4b5aa5d1a6d3fe68c66458f4de944af3933281225787a95ec215" },
                { "lij", "36cfeb46cf931eeb63c91dd4475efb1a3219a7fe3d1107d086f14565f78dab7383e4eec58a0b67877d236b87ed987d644719052857bbb64ecfcff63d03fca551" },
                { "lt", "c25210f3f600d90feb6b234e7af251bd1aa372c70a3d216c9390b7d638d573ebd2699f45df7154fbcc5bf31baaaa6bbf5dbb25aeaceeaae43dbcc563abc6bbba" },
                { "lv", "24d5eb8b645b105e01566aa84a466a41aff2273f0d979bbad7b5333747b7f985e11d964d27e435ffa65aca3e1cf3561e5aab44bb7eaa2f2c9b99539d85ce58a1" },
                { "mk", "79b48cb05adfb67f618378cbacc8c5408af985e5fde811cf8cbc8b150bdf5be7d044bb7ab35cc21c755d8c70bf148f4c9458705d0b8f641416a66aa0ba79b788" },
                { "mr", "1fa8e1bf60e841910fb9373e20ff7e7086ed74369281dae70259774d7a239d87547593dfb4f65ff6c9b8d3f05b0ff5fe43a4a5738c9abc8ae8ea76086b5a3bc0" },
                { "ms", "d27521788c11bf2d6264b6e18d6634b179ea73464c5c29c1acaaac26e3a28f64681c65e7c6b3b5c098b3dde12ba9151b87a9f9f093e1560b25e937c1d56754ae" },
                { "my", "bf8578a58338347e1a3f6e4853324d795d4751567b0e847f5d617352de0a6025a09bdfd6c1e34c110063c04fe81f383b69f2fb48db2cecfd4b5f97ad37bdfed3" },
                { "nb-NO", "f2b119b64a5ae00fb6e13145f707cc567b8a4e51423906fec3908a00e8de2f41e57f6b56d78e72c6be6238df0b432cbe082731959a30804b39c8f0a32aee5a52" },
                { "ne-NP", "c0f02df45f2c146d8691f53aa19120a251b3cec65bbf0c8039e03b901459c1d0749641c7c2e99ed8efd40bed1f912f86a28ede87371ba4c9c2721b4a6fad89a9" },
                { "nl", "ba85c5b29fed56d1a8b53a4e26c251f6da010a813ed9df91c307244641b9c3af2d26df821164c8a0712c9a58f162eaebb6545932e4df79e0db215273181f677b" },
                { "nn-NO", "98d2abbe0d83d8b8e3da75d32f619a93a527a335baf41e55ced5ffd0ab4a527b082edd00581f5b87d8c3de3cad5e0a1e2e1f421d8f366c836bd17aa66c1c23ca" },
                { "oc", "a1208df79cf3ea1503d06011db235b2c501b2afed6b13f121a0c64f6c03da173eceab213057333dd7f875f06c7e3534013fb20f4b2bdc58c5eec31387c3a01d2" },
                { "pa-IN", "9a7530b9e949dd65cad10abbe00c45ce3bf9563feda820f98e6c0d9613891f7d92d656bebb38cdc29e92369aedca2db097252413fed6dbf88b7f97ef2cd0a631" },
                { "pl", "8d04092489e8ebbf894536f21dce2278e398b895bd9a390654b36f8b4c5419c19ee2973edb5471a0485c6807a4897a6fa44a9e5888d7deb324f22c1bf481d515" },
                { "pt-BR", "f3c6b865b145424f39967e77dd2c230fbd86804f6cfe71847c2570c29338ee3c4c750cf126963c4e2573e3bd1e195baf27f221832954d8486b5b0e960455b82e" },
                { "pt-PT", "7c632f381a3ddddacffd20809364676ef32b4dccf39285acd6b8c2b6ad778ab71409775146a9c91640fbdb4b17e18a56df7e9f469d08c0f54e33d259ab5b1dcd" },
                { "rm", "c7ba129dd239db7e07a8cc020d838c993aa8330434a899663ee43a15bfb77a2509fe74a804191aeda1be02dadcf5b3eab331721ec1c976270385fa3f5fd0ca9a" },
                { "ro", "2ee42c3f499635f1379ecb0240bf78c4b48a0c17623718dc436e996b539f9951b99a0d32dd8a3a14ab6322d618f9714fc1e22ebe6ce385241ed1a8c850be62bd" },
                { "ru", "f650c99c36202fba2cad7f390f7278fb486c97b1d9d52d5e68df94680c68be247a43f114e2c4e1a24ce551b2b699e3447012d92a6205374ff97b2bea10278d69" },
                { "sco", "01bd40953cc4bfb1f98368004fe0f60aeed52c21d16c6f5ee42f5733d065d14625a3c4240e2b230486ea98b9b324e57e52d39333ee14a634e67502b7a2a85e0a" },
                { "si", "e125d5f1b9bb199768da1abf274f29bf9510310147963a6b77cf595161f9d2e6de3a3b12b6f3494b19b62168db71bb8b72fc38559816a7f764f42ab0e9829326" },
                { "sk", "a868f97ab23d5b2b2ffea4c8dba20d29f53a548d3ee9fdf7be7d6917aeaebc02f4c83163e60003224af764b4e94873e6ac57781390e28f09c22eba8bdd88cdac" },
                { "sl", "d1bade3f11f1027e37ec8cdda9fa5a3bc91ba599e698ab95e58a9b0acbea5fce6bc6620b469e75120b05e215f72e91d04bfee9b16aeaff1e8bf4a78c97cffb9b" },
                { "son", "fc4a8894c8f2cd10b82872dc42be17d2f22b32a1bfae5a40ce69a9cd79f63c6de70f4a45e857f147e497fdca2a25ebe1148c9b9f1dfcac71a23a00ebc75ed7ec" },
                { "sq", "c4efeefd9054cac9ab8c593a40dc09ef85ece00f50a631ab90fc068d12625cea81988090f0b3ab071b07f622340055452d169f1413dde40385c5848c0909ac94" },
                { "sr", "aea161a907f7143df6686ae0fe12864d6ba933a7634402fcdab12002983d721afdd0f19014d255bb1dc6929ea9f5102a75d4f0e2eb7dbc43f66942639a21d93b" },
                { "sv-SE", "f2be8a90b15a0f510c6eea363fe36de4e46aba230db6e77afff8586eada5849299fcb167560ea1337454e9f2d5dd2d05f47fe4a955454dfc992951dbd966e28d" },
                { "szl", "e783be13aa26970ab06a3607bcf639857a8200f7aaf2a3297d266008d9cf271af7d154b4e0c970b0d6b0e7bb83a20084f275fd712831be2b560345767fe1b599" },
                { "ta", "45c0a15654bca60014a238d0e4a79e7639d80b3202b69c1bcfdbbdb2f29cc8ed092159cba0c10d7e179efc89a5c92dd0f7c450ea6b9615a1d9c2c7539b6fc069" },
                { "te", "edf850106a457e966cf4719a83b0e639dca189a616e35e4ef0adb539ac07b6faeafc53d0b9fd60fcb1667f55824b680f6155dfac4b2150e9588491688b7f82ae" },
                { "th", "9976831c5e08984cb2043a644453f29d79c1a831d001b68858110026b2ea3a37f754f0194d4e4553133ae88a1756811d889b20ad07a9191fe92a137c3f71fe01" },
                { "tl", "8c2e5f0c8bef5de085efb773fbb832f50b422a45f4164020f894d3584dc12718ef35dbc5faa18e5c6fe353e2f38f46e4ff62a7fc308afdc88e22d9ff58286b28" },
                { "tr", "6b6a96e3a9ce3b9794354293e182727b9939b939ef722b46760b1bba08d018ebeff203498ed073b0ced9a469e10b5bb2d8a23d7eadab569e92221d71b2d3e2a6" },
                { "trs", "7b04a266dcd61e82251e04fb690561f7d5fe73b6c739755fd565f8fb0f6c24ebde7db832e9a6fe1f72f0ccba007c7f62d034283ad7e42a3523636d2c04fd24ef" },
                { "uk", "2f247af6d589ede6e65e32758854fbcda077682c8d97c5b2d3b3dce69e52063eeb9a16e645bcb5d039ce87578764a2d3cb8cd47b8bd445a19f97a5669d83bd14" },
                { "ur", "01ed3c8587f45a2246f3ddf282c6f51cd860f257158167dbff5d1316e2d259e4a9c36fa8deac99a3f00b9b1f66e462e55220d7e916d2cf0df3dc37552cfc2c39" },
                { "uz", "aba63464c9952d5758462434ace2a05500a42abc10d4b0327d58a73afccf77b941aabd06c49220bba3bbf0364022b411dce9376373f3152a118b5c52dabd53a4" },
                { "vi", "6d49e522ecddaa243c957f9e500819123b167666d8cbbf5c5ff3406cd6bc3eaa7b17e65653f3ea3cf2f6588e5af01c2cb636b7fbd85a34f4f50c24673aa5ffb8" },
                { "xh", "844c52574cf81ee24dd8b54d25956301581cf0b52cebeb2ba20f3269ede55f64615fa6ea427ea79ad6742b9c8ce8328889a06210053857c8f07cdc9034beca52" },
                { "zh-CN", "797791d31127edba5d6b95b9aa48f1d0f676c0c694dd9cabbf7555de77e7e443e20bb9dd78edc2e3d17df2247eb09ae12b3705a8706fc30e95495aeeb89166dc" },
                { "zh-TW", "3e7828c79f8827b50ca0d96359e6659fad81edc6306c3e441d63b5955d63eee24142f40f888c550b4cc4b77b8c820860cefb4aeb2198e3f158e47c437bdd2338" }
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
            const string knownVersion = "106.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
            logger.Info("Searcing for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
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
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
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
