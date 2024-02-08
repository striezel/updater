/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "123.0b8";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/123.0b8/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "67291c61598f0e1330a94d76c563861d16e9157455d0b1949d83d42001188d6cf9dcc5d45622906ec3f5784c42eff6ac44946755dc8d64aa3f85de347772d8a7" },
                { "af", "080ec84ae8f0395a148151a6c9a2ddb335646ef958f75737ccab6f96263db85c7a62be9bb712d8c96e504b94eede8747b1c80121362df7835690ecf2527ffb44" },
                { "an", "44477c1a81021507c412a5aaeb331b6e235de38f02ada6c4b20c08ad2dd602b145baf96ed44dd724c157620f99ef3eab0bfc04ce47323f06a39f477bc59710e7" },
                { "ar", "1ffcbc939a26330540e72522cbc6434405b573d06ba120fa6cead9cbd224fa3aa1e3fc97aecc1429d5d14b3b56d01792e8beca388dcf4b700854ade26307f821" },
                { "ast", "0c2d4584275a2e07158a0eed9d2c8e46ced172d03cb6f27270d45824b5debdf57ca0e933af2d82d9060e44d77cd77704d204995ad852fe8edcd1fd23c456329c" },
                { "az", "2396c3eb695ef79a6d73d68bfcef0ceb76063bf89bff08effa54c07c84b6f3694c23eec34a075b1dbd1d78467d55b175f18b7f05d07e9d815a9f6cfbed910064" },
                { "be", "1ea3ba3df60863110aec848702630fc65c3c2f745934054687c765b1f9a7d5a47a011385fa27a6a7762ac0a07011c5a12ddcc78cfbe9460b4d68a1193d3f2a66" },
                { "bg", "4eaf3c92fa407312f68c6b822f862864295f8078be2a56dda4afc192eb8810dc5521d48ed6728cc468e35582ef8c78cba7117ffc1cc81ce70764f927bf5e66c8" },
                { "bn", "f32876f2d873b0cb01b6fd07fc9904359207610f24b3b1abb9cbdb0731622dbb1c4059c49d0b90693133a0190eb42cf135771074fb6f2e966eba866eec7ebf21" },
                { "br", "53561ff4447b25a44cdd2215276cd3c4c90c2015e29ed253b54d78e856db81d977ad045b695dfdef638761faade20a4f093e06c06f4d197235adc1ea5a065d2d" },
                { "bs", "55b8313d57d28e9ff524b713f3bfafe3c3996c64dae976e7e6607d560130f7409fbcdfaf77fd45246f2e405bb6acd91d21f36a59ecdabcf8e6eec6eefae5eeba" },
                { "ca", "fae4b6d1d16a752ea54e6f5bf2810636723248c4b524efbf2d4866c51f48dd214def068c42e2bfa2b312eae823038f1db8c8767690e9277559310ec3bcf12e31" },
                { "cak", "e272c21d08a772ffc152333b0dac86a1e4b4a6bb446a27be7dc418ddd19b519d1288310bec4c2456c0a53f3c3b1517f1c8c9ed4db8a12c9ca3b261d76502d481" },
                { "cs", "e3b8367b88a8b5b950f4d2f67470e5de86c357cd0c3942f299ece7d66a8135c988196556433b6fa29d265cac2acf4399cbcf6709648f8af63e504b8adcf26624" },
                { "cy", "3b150046d5051bfcc9a46d994eb2d07e17790fa3feda87d2f0ff19c98c9717c2f23958ecfe3e1c6d608184c834e8ace8a86bd9af03e0f9a8d17ca16399f9468a" },
                { "da", "e00f5989c5b497102a3f4cb865cdc221ff38ebe349f42935b4298914a52cdd0f386b4960920b02033471dd59c3c09ca08cd8e2d3d30ddd234481c36ca56cb623" },
                { "de", "33a2a5b0ebdb8b9ef924f3797f2c2e7e617cb07a7165eb5860d08ea35920e5dd655a95fff92bc5bfddec94c089f6c1184f83099ac467d34b51310598b451857d" },
                { "dsb", "e7bf2c37667e8fd9ac027ff1e5bafab7e9d6a9defdff757e36c201a7e885bb53e5712fe9a82ab90e80fec512d22f4c0559df9958d195c5cd6a4a1ca43fa1fe46" },
                { "el", "1c9dc810cbf23368c2ee2a8f3305652f8f2542a9a8f13871738307789b5ebdf51ffaa650005dd2dca8d5fec9e27e6eb67a307424cbb19c092ddc31d410b3e665" },
                { "en-CA", "fc3c94096bd9d7c4cafe7e7a02cd691f3b2a922f10780c3fef7baafe1f97eda071be7f52378de3d5c0c190f9053c7d4cdba8b2be125747fe788534538df7b075" },
                { "en-GB", "6b315295030e9b182a1647cef0d3629c459164731b6110d486c6fde4ef4cf4da7d2d2036e2a8374af8edbe0bee5674b1f6ce47ea77127f31333d248ce7c3ed8b" },
                { "en-US", "26a21c71485e166d3bc5c75891bd17cdb1fd4efe847c0d727a10347072c2bbe3b45cc3b27512bbd1b47000b48e6c72adf00f49fa75e4a0324481c0f8627c47d3" },
                { "eo", "97b89edec7919ec9ef4ccad77c85ad458d6803b7a32173979acd77830e355d40d1b6576aa6501d6454d096be0acd3dfa472c5ace4f4deca4a628963d67f0e652" },
                { "es-AR", "957e91392905901f669a9c1062a0566d9adeb32fc0bd1c6fcd95b8be3af0ffe471b1667e4e9f445f89947323d08f7fd9dab09c7b59cf8e74fabf7b626011d5c8" },
                { "es-CL", "99c1218906a75029d8b26dfa1507fc1da9c12a2d910b54aa463776bd8cd6a1a70d3d1fc61dc55ec49c9dcdfe9093e748bbd29059ffffbecf8f87bac236d046d6" },
                { "es-ES", "1683e02d9b95020062e6394af7659bb52654ce56e5ab7cded9c3b1b05cb78342978a23b9f0a422cd0da8dc1749cc608dc05916a6c8533ec2de8f90fe3250b821" },
                { "es-MX", "172e559005cdbd274061b39b6300bdd030a4ecb3d42750dc7be8cfb0408d60593b253e562282a663099db7078f15453158f58239724296db0f46aafec7161066" },
                { "et", "7d139a02ee457f3a157ad0253b9ba8e99470e8f2822fee7a25ac49e2f54fe8ab4f47a09d4bad8423bb66e6092973bfe9d37cf539106b1243c07cef0f6bbf0671" },
                { "eu", "1fa74e7890830ebad7908cda45c8591aa16ea83dc7f9b4509ccb95676db3a4ba3e422c8650c089864fcaa7d5e7581f4d3e9d33abe8bb5b667922cb4a0c221cdf" },
                { "fa", "bfcbd190dd59004f43e9a48ccdeb9b1e9ce2c180f1b6493422207acc6ba2e05965880dd92b687a534fad949fb1d42ad50e66fddfa2ce578c4465be106049c4d1" },
                { "ff", "e1d4d1f3e3950b7cbfc6788dfa18595feae01e402dc1740a3c86acb658bca7258cf186f5e46b8f611fb9c5d8426a9754f4fbba30f4cde7a79aebdd035649c15d" },
                { "fi", "f457480d0e91780a6ccba04f33c842a93722c57e866f0a66f7d292d614022f2d18c1ebd75999c14c9f8b3c09badd577979643e5d65c7db6c83126535c4c02aef" },
                { "fr", "6b74a21d4f34f763debbbc57df7628ad7978d69a27d2db8db0a876b5263145d8759efa7e638a2b1567b500ad1506e103a2670d507f6c5decda9a4a64e210d8ee" },
                { "fur", "3221d5c2eef588a62ce2c438c2a603e48e10c28d73fa23f62d9e2d0be14bd4e06249f83fa97bc6c4846f98dbc00d1d534044c53fd4372adbd2e4083725bc3932" },
                { "fy-NL", "ba13617f014a96e2ae613c2ec1791d57afcecb28bedda84f75943549bb997fddd09ad3d19f6465027ce3c63a03b159deeca05e9e95841607e3ccfadf810fc8f2" },
                { "ga-IE", "08c686d7ef369845b144c7109862951f1794945e343556dc383511f59e4b8ce7ba7ebac9d9e5490b27c099bec44115a499621444c329bb287ef298537d91b5cf" },
                { "gd", "558b7df7f4c300217de4360b4535c24381191e2fad627e2245c6209bfee2feb2c1855ea1fd1de64756ca057af1d6ed09d4d79bf60e9a6f1da476e855ada90074" },
                { "gl", "57017f0ccc342ab8a0826aba990cb08da7d99217584108a25d946ba5ef0b37ec009a68a64be555e8324aaa600423b4b35c28b600422bd139ebec24b8ea8c7bd1" },
                { "gn", "ba97b2efbfcec58d3de682889bcd233dcabe4e09082bea1b38267528747528b441d074babb145f609eb17bb8e0ab607ace6d455e57fa98901947525566055185" },
                { "gu-IN", "457c01f4f91d5fd56b21f98f36d6b56417fdbc8cf0302dc67b8c933283e5af37c84cb03d178200580c874f1c678d8ec99106ce6fc1bfc46847ff35cbf3a1d953" },
                { "he", "150911097b758130df54f5eca796a1e25092f39930a7f445c8de9c8a0cf7f5bfd29a052c99768b86ca4e507aabe360aa6ed4fe7f77462ba5b8d955cc1ca19604" },
                { "hi-IN", "bea527e87abe9522ef8e642c5cc767d949fd1d822dba08751fc33dd4baf7b7b075369f70f1a3fc822e2720fe4f7ec50ac8cf1166811a4ccee4255768db44d77b" },
                { "hr", "470ff660a26f7401173a0d12f44b870db03dc61c767a698b4bf12f7a77fc18ebb1c3aa4578f6c567d2c4b95133715ac3e334bce8fab3da8017b800829d7d30ab" },
                { "hsb", "7cb2b6a3b16ff4d244f25190aa22048ec178ca18a49a89ec77f269ffcc07615a0781b1252d4d7551b8a59dea44dafebb3a637362ce723cd356ccac2639e0a0c2" },
                { "hu", "eff9bbcca5444ecb456dbf1102b808cacdd2f8809f3bf157dc5e66e299b240ebede4c3e802ffc6e674ff9283b71692d29277f0ec9bc9c63ea71883f3d30dfd51" },
                { "hy-AM", "0ed52fa1f73b340602e794a1c4e1d4e5ffa3971528d36dca77138c09e588c65a88d5dedac38f8eab0b31a7eb5b4e480bce887f856d0944b834c67c538055a364" },
                { "ia", "f1d6bbe707d0c3aebdb4753653c07d5bfb706474dc7f756c7487a84667e6f7f0ab9235de154bd7561e9b7386441423226e1c54bddb7ac3762ec835657515d164" },
                { "id", "c35e06e76640c82abe036aa6d4e570b70b6125503adb519b2c3881a338472f698fb00832882ca9d68c6e7a73184b5fa321ae327bb4aeffbb22558d58d47cb4f5" },
                { "is", "7e87e602a414e91506ddb048b4c941bf7e2099024499ee990b83b9c7f72e45415455e6c258f24b73ecc8af8241ddd48cddb490fd2c70c0f7360de39f547eadf5" },
                { "it", "ca072c21e546957692105c4d6b255ed86aa3dcd7ed9182556cd94123e41e93068a98c7be74f8fdd7c68ebbf3f96ab50e7552d8f036b3bad8bb3392da3db7dd83" },
                { "ja", "5d2e4b765a82cc470c8ec1cb66dff584280bff6801f861725c1c047fdec8d91dd07dc5f7e2b896e089298704d7689019df26eba12433c6532a8e3014666e6130" },
                { "ka", "85b1fdf3631d1b249cea621a27003cf7ca05e50735bbb6f9be214f0da9d0a6de347c128c5eb18fb82aabb92df902db62d05f53c79ea756364ad534f376a89316" },
                { "kab", "5626b20ea9d8330782e5ff5741c690f1623c6c26171214f97bf0d571ef32e8eeca6ef1227f2cb2c60fccc52799d890587f087922316c79cfc619a1a765f31637" },
                { "kk", "68d8f27462b3c94d88c35b4ae609ad23a731a34e97b31805ea3f96c60fd37ec3c69f801e44805be1c9496695c56bd55d368254d0035ab8b915a44227c19b60cd" },
                { "km", "25f4ad5d968cf5a002ffe9fd720fb8da47354d78bf01aca2f5a7d30c90add0cae0e7bec1d741a2c25415df30d31660558dd6114136a318e0c40a5523a4479944" },
                { "kn", "948002b6263dcb17b29e7589a1befa95910bba8d27eb2f3268e8c834fda07f73a507c29f4af150e88fd9a4f5a2fdad7be0dadd92ea6e8b3aa911e581f1df5efd" },
                { "ko", "0872d7bd6daeb4d90b96cc177fb0a850d2bb5d728f20208210d83d6ce1ab51ba80691bd6f298f393def4b887ec6593988d1dbdd4eee0fe43a1bf941bca776872" },
                { "lij", "389e7374cbbb92b523fdeb59b1bea5c0e478239a36da2dbcf7aff0fb6f1f53ec1c90fcac8a9719692c4057313b4495db3b65505689d4d080f5c936102096237e" },
                { "lt", "b7633dc3c6c7f901c96ff3d91e66855078079c05ef75a8317cb44b9e559925c6c83aedfc909622ceffa9757dc0f142ba489a4245eda87b354f22b6e1e22a348e" },
                { "lv", "6368f58485777bf16b4cd60283e54258d47bd9b14ea6558c97dcae6d56268db1bf9411a05d94752945fae87609b5c0ea22ec399e2664cae15c67400c3c0b8009" },
                { "mk", "f83088a2f8fecef105649052a306c169d851b8f9b6ae844fe7803a331537d1808662d4fca876f2ed1be9cb7c3330cf2185a65de7de35c0f99f6c9033de75dfd4" },
                { "mr", "59a3c7c77023be37e3760825f2c785cdc495c889b9d687f24a2181f42b2f00d8dc537a1d6df760dae8980e1f5c113b24fb0391ab32ca44cd676a9efbc4d8475a" },
                { "ms", "08928a5baf0aefaf1a6e1dfd590af21800791941bdd84b3c0ccfeab5962780b8a9f82e10bc6d24094844f3a2ab78d226cc8e792c5ee8b36078cc2c1013ae3bee" },
                { "my", "8fe89f56b1efec60ca525fcedbae331eef977a406a2fb8c6b9c22d865a40167d106e0b87fa638a7c14d6a729e39f2ae9e5ea038f742d268fe349f6a2a418d8b3" },
                { "nb-NO", "afb05a4e00b313fd1d9b2b5cdf0fbe5668aa68eafdbe52f6a542e0057896477237e022172e9008786ce4874654bdcf63827039fdf8fb09ddabad970aa848ada3" },
                { "ne-NP", "90a7d012b0a34032bbf10978ea63b0870dc7dc9d9af3a4b1a2b81e91fb0c14274f973a5ccafe2837716f852bcc19c104b5ba88c6d3855ea5672c65992056e739" },
                { "nl", "a3cf81b6d3506b44b9b04f2563aa279cc739b2ded377289b811702da046bb5d3b73b8d10ff5c9ee4f3ab263b11d2b98b2f2d689f4ec03790bf636fcd3fff1c15" },
                { "nn-NO", "b7b7ec3d531ef0e71de3b5a50c7de299d5cac93be0d2c1d57591b270b2900b78bb626ecdc3f441815fd8fd15e89361978e9a5720f643ff4aa590df05de8bfdce" },
                { "oc", "57e9d50b0e5bfa88c270a5b023fa8f9144860d08237e9a4ecf54362b05b5df1288f73a2cb06ebc5c7402ac7f5e12b4174c6ea8b6ab71549cc12b61acab0b8ec1" },
                { "pa-IN", "295c15af755e78352104869e0412ed4722aac1be57f27a145ae99d08662a40e72b2fa1ab0fcec753779d5d2a44243cacf7fe94510c10a80be8d0d52741b5388f" },
                { "pl", "febf9ef93a07162946aa7b29912b353ef367f1f43730aa1c7ecce61dddd72bcfd7ea32b565b98128d48aa2431e62a0caef9ed4593020f338922c814e76095a7a" },
                { "pt-BR", "4d6b7f4c9c41a956f5ab8fd3ebf681bde81db622b63b428af30153f630591fb103314a258727abdee2b7510620dbfbcde2f47d6f6a6d90e0188f8d9017f969f7" },
                { "pt-PT", "db6b1c4c55aa40b7616a4f1edd23c0dd8b187c7c50e7bea8eb651d47f0b2a270dd1a41e3325e0f62648a0107bf88e6e29ca0021db221633ead37c96a5a95c9d6" },
                { "rm", "caf99aaf7c7e87cbac8f03917ed565047a40542f09f5891d424a33bbddfd418ad98ccb6d3fbae5c08f10e5e8b40412e0f58feea6f3bc5db32e1223940d71c3fc" },
                { "ro", "c2471c264898855b350d174e29f6f11b9d6c9302189d932778a850b97bfd61e6ced9dd0bb37f71ffd42c56963ac41f54a1e5e13e872b3ff178c2b5ff2880973c" },
                { "ru", "f8d0be639caccf9eab551c8c0c5b30da8e59c4f45e62f96c1017a31813d413a244b83107bd919ff93669e3b6c3d03d028c9182e06e905fe40319da1deac04ac4" },
                { "sat", "f6ff15ef1842f8f80cf6d968131aaa67dc7484b2b57931cf2f29e9570f4d49dd261eea9dbe760751dee08a541c2ef2a39304b75261d648ebbbe63c5f4907ed80" },
                { "sc", "86dedcd792239f0a03d14684a4baad5ebd834887828bcfcd3f4439b631f4079a0366d7a0c34ea114dff935ea488c327099281215b4a39d30820af00208c72a6a" },
                { "sco", "4d572c254324bb3d2f5222cf0eb4ed426779477f7a06f8a91544bf9485d317d5914de7566a97bc17a5676c93317318a1f67515f46f8a6d0ce750f36d2b2c19f4" },
                { "si", "35cbc7cf0e8aa5862f3fbf416ea89d0b3929d7173dc4da7c9bb3011f9e2c46f2a03d99b70a6fe1623547eadedb4a556a6ee8ba6aa3336b3c76d3527a8e84c3c3" },
                { "sk", "af4e110e32763571f311b3b1e0bd87e1531476319d919eeb3a32cc1c68f2038e9fcce0b0c08c3aa4eae6ae8ce3f438e5202788cdf90686563606f593e35331e8" },
                { "sl", "8ee390ec6eb4c9250804ba258d1a63dfcc47f1af48ab739767e279dc6232fb44a69470f97e230d43d52fa4735239d9a8e229c2187525fb99df821076b5ae8740" },
                { "son", "7d80704d1917094a5cb252a5d9eb186e9d32739ac6609df04fffa0546b776e6b39345e3644c41c32470ac5c3495163ae7fdca0c44623468d53fb2550822e5d68" },
                { "sq", "1754a6c49a1d945bb57038a4080965527019fe60e7a65a433c6d405427bab2f21d565c54e29bc8c05f32e73e230f7c2147470b6b9f3a660c5dd157a6a6eed9a9" },
                { "sr", "f27deebcda09cd554ea98bf675cb63d908bd0ff07a60a5d586df8cb59eb32c854673aa06fa4bdf8aed092f0016b4b6f18095862f58bbbc941dac8ca32a827003" },
                { "sv-SE", "c53e1a1799ff17e53cef85c91057ebeb778e017a99027a0e4f67ac8fc7ee309715819cfbf78d4fac5f6d9cffe9ecd6985fb3bcb56c4c3d4dfbc92f5fa0899084" },
                { "szl", "40aaea430fcc7217b578cf748696b23becc806e1e2164d13c26e6a82771e6201c6d959c13fba4fb086f764d74e4191afd57eb3783fff7ee887483881a6565b69" },
                { "ta", "6848c1b403b50cbf5f8322e0c62968d34572de144f0900755a9b5f73892b314c53a3565aaa53576b965d68ca164b9b02bece707ab6d603e86d4d179d9ee07bca" },
                { "te", "436bdedcecb06494e47d3a6b60f3dfe41dc2061f9623ab56cdf6a407a9ded278e555fc1713336f25a9225250ee5b49e4a06de3a36e5363bb0a92c1d02e747316" },
                { "tg", "49f357f83412082039e899d46f50dc07382e83b3b4febda04b87aa5715601f9191166e14aadb518847d567215d73de5511e542f5f8627626ee9a91986b5127df" },
                { "th", "ee431b0bdf87202c9ec154acd935ad9a4270f1e8c27a3e8ef3da1b85caf7f767c5d395c359221ac71d4f7b13ff764a886203bb6c97631b5159c2f293f361ea7f" },
                { "tl", "038871714f59db8367a125f75d57cdb73c7d3debe1abb86a60ddb274b90979a424260ae22f0bb0a81fc56b08cdc112b68b663b00b4a670a8b23e374edcf34f5e" },
                { "tr", "0f219b852564d9d8604b875fd5a772019add8eb8ff0ff8c7562962134577e0879dc39dddc774aaf8f18e1c223def234032fbb92cf12a26394cca9953185c4052" },
                { "trs", "81b5a5df544b8439cc4c056f1d9f41ba89b097e30e4ab2dcc5ddea36155aa53353ea3cf19c7ea4d9f069ccded4c7033697c7ba9012cc804d8480ce5e39948af2" },
                { "uk", "57c2a8c80db263b85aa36335b90bf72a3e9ca18086f6353a436ebc377def7ca477be91cfed91757d304fd5756435b1280e057992eb7d5cd70d35b1ea006d0703" },
                { "ur", "bacfae3067320988ff9aa859a1059b95491a15ea64dcfda07cebc4ba46d2489bb20b02aef0523cf41cfc5a2cb7f605c23a039bba6b98b6c81cd2f10bc0f12cf3" },
                { "uz", "0e9df065e353340ea2d20761761fbd83504ee439777858b50b5951bfd803f3fc829eee0cc1346a37e9080b31f7d13393c896516b7500b009b585aed186d7d093" },
                { "vi", "7bd92d58863747328eec1c27aaa1096cc232578211d10eb56a45c2bb891ef9dcf6c078a1056783ca61ab32381291dea01db17ad2f854cfb6527d84eb464a193c" },
                { "xh", "96e02ed4c7d546555fe93ed2bed888ec31d12e3528597dcd26e40c8ed5cbda66cf68959b1a97facfe0a15dc1eefece17402a8f3b148f216f29118cbe7ef68e08" },
                { "zh-CN", "ff599fe4543d1180787bc694b02e0becf8cd09addbfe3b1f5bafc7c716538d08f61d7d3d9f83d14d380ba750a3ab872044fefcc6444d13ca43acb1ca59f44920" },
                { "zh-TW", "bce59f506d45d54af50d6fb91d3d23f128892af9dfebdf82d6a0e64c02bf54f61c34b9a836d145db610a621fbf1a87632f9b1162a3234de8b5087808f9ce3aae" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/123.0b8/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "1d0fbd205dfc02574bc8383baaab22eaa8172bf4f13747834ece1b3fa44eb5af638871e4c59917130eeb80f712f7994b3ab45d416a0d118c98749142c3526b2a" },
                { "af", "e4b3b37c5fad8b82a978a7c23cbdd61bf29f9884d84407f251e3578e2a1a4d3f7639e6b080492cc63a628fc2bf5171d8e123f4e1071c65d75699d574601e8ade" },
                { "an", "06f21b7c35de30931fcb35217883b8e237ff4369f514bb0d0d09b8706cb9370c71039c88278280b55b214a4883c1f514bce5adaa8e12864121cc6f5e689c79ff" },
                { "ar", "d1629a4ad1fc354665db4e9a3e37e5c4c0461791beb683d7e6a5697c83788c30c35425e6eae33ac9bd88384445fa42b7106a06cf6be0631d613799846a27a8ca" },
                { "ast", "4d9386ae07b16da1c5260df65df807783056e86483e40d5015e07c79793b2279a35724cf49da2799aee18472a1f8d654e6153adf35ae383c676175a36e5d8491" },
                { "az", "f4db99437a98b43b27b66e7d6728de9d7e1d07f4cfac700c45816f5f664ebb4a238270de7fbba1e63514aec35da328b9692ceec2c9992e29da1e420ff93b5e69" },
                { "be", "2515862e2a827ec507c81becfbdba16021f5ad8a39ca01885d7668d218a4abd3ee3a60ff0b9e0d8d7c776d5ab6289401c8cbc635ae9011d09aeec22093039884" },
                { "bg", "cdeb0077231ff7d274c0c0c42124027aef3a011888f75900759eb5ee33ab7de78c47450b85dc1eaacbe444bc2bf8352ccdf0a7466dd485871e9db4bab8845420" },
                { "bn", "befcd074ef9d020957a883bc57521e3e36fba30bebfabe79a8b581ce598a4da679fd4b7f099ba6ca6e552460f333543cde375e228b8b5dd215c2c3a96c790ad0" },
                { "br", "109aa61c6ee41926060eaac17c9154d8878ac81b08a982b69529ebe3c1ee241c8934ad28aa6cc78f3cbed2d2b87d79f07b988c4fcab06741fedfb83fbd54a526" },
                { "bs", "53595d193e71ce158380132ac37a2c16258a2e332b4ab7f347f368a9edb9938038c11d3f97ee3571f762c9c8b024565e2161484031a6861cd4895b9e16dc5c42" },
                { "ca", "eea7050237b7c6850652a27bad90f6eae19776ab6e451c45ef6f71dcb33ad90e8a5e667b4d8a400ddd5f3634f5527ed8a23d5d9cb888b1b6c92239eae57a1f2c" },
                { "cak", "9b5d117f88ae479a28656769cec9d3e7b59d35440c61b633e2c43b2103642dba10185ef398026bd77fb2fde725c1b89e1b2ed30ef44394cf9bac99184e3a60af" },
                { "cs", "a030c53dfc0fc830fe421a9b79070dbc15128c70af6b147b7fc15c2a81b1e2b895246268ef291e63565a9f757d030deecfba2172483007ddbc6cabdd480e5a50" },
                { "cy", "b640e201c339c46600d755f40f6948135c8fa408ecfd7c74a5f5d591bed16dee91644a79b36d4275446074a89bfa43c1e119b724797455328edcf3fa75bc307c" },
                { "da", "ab416957dc09fafbe7deccd1ce8c01d32001520b00afd2f19e11061b9491da163584e43f6663253ab2942e00f287563c0af0d33b2ac59cf54c2ba6312090a7a4" },
                { "de", "b322f82fe1bf0d074697c52b71603b4094a637dda087c9d7bda65beae0f597921843bcc1fde62786d60cd8e45ee2b1de606ebb99543095c615452d2ca1275978" },
                { "dsb", "8b26bfb063a7bae58ec77ff084ef4ae86212970902e7f777eb9cb9f71715e16481a4afb5a53ab719032e758aa629a4e77c8553e38603b7316787353a73793c0d" },
                { "el", "a7ed577486fc19d284877598f84a729533e59c1efe931574c0dc280d7f6b8050d537b51fc93855ad444bc1141acc2ba3a7a1279ed300cdc75c5799e37f5ec6f5" },
                { "en-CA", "ed3b534d851c14a270dfbea7f614c3f0978e7bdade69eed091cf2a6faabd0a0b45730f685938a267484b3e3bc0e477fa4d3d092d681cb2b01c04ebc37fc71423" },
                { "en-GB", "a7a2e71de13c7cd4fea4b549b26b1329dfdf9293e4ba14d5bf3cc8a69e2f8d41ce6af6129ce905bb836d3e54577617e61a8a62039527032de61da176f91718c3" },
                { "en-US", "cdaf01d2b10b9ae2a4ae866a9fe4561c5fc4b7cebe5a988a90ddb6de59a860cb030ca558da3e582f8525856e9c4e86317d9024c84038f4313c356bf4376fff67" },
                { "eo", "e1a043caf7e908ac9a30299284fee3e4fcd4a11baca839714b4c0988a86437a20f56094867b921926bc1ee1107a72beaa6fb2abfd78f739ccf697e49cb9cb7a7" },
                { "es-AR", "bd831e514fca8424ad550614d5ccafb738838b413c245dee28f96d767da902046f97b2276274a1bccfd73e659b3cdf37ba78610d530054695f420c6151cf2ce2" },
                { "es-CL", "8b7006ed65330558712f62cbac0667c806c5c47cf5e92936a6b3906aa97ca22a24c03902fe64ef205d16821b8b39f93741e03ec284f7cf3788644ecabd75c199" },
                { "es-ES", "6c04bb501a34e2134f84c3febb8dfc74b9cff1384551db842ab18acf7c44a75ba8ac3f097b257d0efdee33b295b17c7a422f8a48cdedbafced4337fa08263c31" },
                { "es-MX", "8bae8637fd8eebf3fb59df3c4449f1d8e4d905c54ae4e02e26432fa87e373a22226c1b09031b756cb903950632932343a759a96b67e7ac3a09e1b07140b94147" },
                { "et", "83a9d9f4aa7f8ee63892f7581c93469ac8499f52ed6baac4da857dead99a87ac3a7b0cd3263e53032f4c76d4b646498025ab275b5eba470c3caa53c3a9ee2de1" },
                { "eu", "441658437239274ba0ec5672ed9b86cd84bdd9a06fd31ec70c779e57098e8e5a30e3535db259c845cb69d760b3bd66db45268852ace02dac0d0d17815d52aeea" },
                { "fa", "e80dfc08192e46c97979454456beff1528fb98bfd4df03efa64797014462eb3cc68ba5217c1bd9d5280d2482da9191ae6c45f59ab44f92eb71d8239741e8f9bd" },
                { "ff", "e266a7008aea29310977440a514ee5367282c2d175debc12e9b55a3af15e47f10c1d8eb4fd2f3d210e554eecca3a406e0a67b0e8f33919361e8842a5b440790a" },
                { "fi", "d4cf446e91599a12c44038eac9c8a6b81724659dee17a5dfca6a4f577761647beb90a8d76d15350fdd8d37dcdd72facb200d86ecf9069b67d9bc51ccac441258" },
                { "fr", "6e726b13fb63312da0bfd9baff130b42117471e2f3c4d973aae0fc6726dd41c8c9e4bfb2ce4b0f0828a3657d812e707febce3e46e996aa65d951601422f59908" },
                { "fur", "830a2f1c68a7caaa9808c17c2dcc303f3325ab30b09c85bb28f093f89f764c95b034ebdca5aabdec2816842fe52d8c7869247281a7688626e18526133bb65cfb" },
                { "fy-NL", "1b32106f8ab26f7cffce847aa78473fd3b3c3d497a204b18d1685176ad1bdba8c443fa8043d95398cfb85887388a1634baed49ac5888169a11fd4b777a398b3e" },
                { "ga-IE", "a5225cb15d15ce55db4da69eb788f6b3f85f6f05f949621da42b2541a90eafd884d814907617094870792b41b61100dede8d55fe34c843a562997d49fb51f881" },
                { "gd", "bc09223f228353b4da6b31b17c32d97da1727cc947d0b48cdd686632704552b94cd60311b7c7f4887fec56bbf2b62cdad8b29e475679513c60101eeaa8ea0782" },
                { "gl", "f21d4b008153383391369901b79c37d852e5b4faacce20d9ea13e333b966e3cd31052b0b3b9e1a1ee11647e1afac8463d98d32565d9eb1d2c9892722d0146748" },
                { "gn", "0c3640722ecabffa066d7b24fcbda9821827293ebc0b799028032d58e0ddde673840330588220aa9163a6e2835b18892fb77bbaea923d2522bb251d318c696ed" },
                { "gu-IN", "191252b3cb52280ba22ccc3224f23ac207677d40888c064c96e06ec35dfc13823db3c2b77faf04dfe9e800f54cf22ba60f70ee4dc3aba539950621d0b03bafa0" },
                { "he", "eac7f9f42582619f3207b2dc9752db65e31fea99b2ca0481befe66927861492fa56fb5281a36ba0800472fcbf51463bbc3e4ccbab0a576ee4bfec4d913366914" },
                { "hi-IN", "5b043b28137c3308c1ece0e6532cad52da9007389363698bfb1546d5865006490a37c1cf1cb19fb009020a45d9456e88773ce08c7869dab1245c17514512f5c7" },
                { "hr", "a0c7482db58472e9b72f37bccee6762bc0f5bc3ee0a7085d63328a7b8aa115d490323b3d8ed841a7ff4b08efbed4f4ea33fb9b457a2b7272ca989e9f01166126" },
                { "hsb", "dd3c90f5e50eb212808ed0b8e7a17a33d8e54e859d2cfa1b6c996e3acaa49aacaac2365cd1ff60a2cb0c4e41a5f20440d72b3f640aa09ed29a91c3e5f07f2911" },
                { "hu", "c084ba3ae139c0b8d0e0e1c695e35409447b03443460a3f8b470880fcf21fdf095ba540a4e879fcca9f557d8b961691e46e6bcf61a2324b8bd63928d809ea7a4" },
                { "hy-AM", "28db78d94be19c66ee235bc23256c72b7cc3719207d3db312d8b18bdbc43794418700705fe1bc3ddc01b61db650d8e3c95ee6de2d2fdbddb06ba94bfa8034f98" },
                { "ia", "9136373db7170653a3088f345a8b2711b7e1c8232996f95a8e21bd43dd95d8405dd05f87c3179bfddeb043dbba12fbc7dcf00a7b2dacc2fa2545bc374c1ba730" },
                { "id", "203d7c4dfdc4a19acc517d0ae575b0225b670b397cf9411d706c17e10e8d312e541e3e0c72c24f07a4cca0f1676be48aa654cc444e18dfd1ae6f4cd351a147e6" },
                { "is", "d0fe2bad417ce194799cb5493e414e644a53b51be6195786eccebfcfdcf284d644d745179815fc78ae0a7ad675ec514d793592ec5870e49852ad769cd1ef6d91" },
                { "it", "388c0d6609710be63c2ee5cc18760bff747235340a07b2a8bcafeb1577bfd41453165b7b27891b3af902c51e08adf156edf23d4723553059f41dc407bf1b6873" },
                { "ja", "18439c933e60f93da5bbc5c971eb6fed154501ef11b0ab7ed6653758908c1312ad2f32bb9ef7a4117eb66bc78417f235711e19d2de5718a610d8fb907fe96c76" },
                { "ka", "da270df9637db3ef1adade35c0dfc020d124b545f34eda68aa6b019b972e3feb88498f66e3df3c8c9553c3215f0207489b98b4611060d8173507cb80ca18284c" },
                { "kab", "a121cf9397821df33edaa025ffac93a6d819ec147f9c0b15d4373c64ae1efd31e9c64d822583e534db54541af63abb9c19ce35ebd1b299e3c61c90d9ca409b7d" },
                { "kk", "f94a999bab07ac70a20ae289d62c195589fa96d51a3d13204c5cc11ff7e20644d4c18c7af36c3ff0008ade433ad2d1a811fda5c0c9e6c1ef717373eee73b199c" },
                { "km", "07ba7d98f939928f2d33d2802a6a1e889560dc31225d13911599aa5baa9e7aec9e6f714d4fe8d113fd3b6e05b9bead55c1817dac64cc5c456af986bfad84ab2e" },
                { "kn", "8ac43d8fd82a7dae2e50103b9fb0dc92a8cfb9a4a47f17adcd26e58603bcd3e18612b928ec21c941a037a657ae03c7823f8f133fcfb1c8b0dbb95a77245f8fab" },
                { "ko", "3145d1bb8fe051258d53df30aa3dd3c0d842bf5de636b560bf02afe55e5aec4aceb74c112dd9fe9e0c205bfa2a1f196a00018387d71c0b0945fac5456fe52a00" },
                { "lij", "7ba48ec9df03ee66bb7044591a5aa7f87e190bd2fceeba9d573fbb659b340cc187d7ca8fedcde7fc4c9126b39e9340eeee9424b8950dc49b70fb6ebadb66bca5" },
                { "lt", "a311d4860ea0bcb157706e83f1f768b73e3798bbd965634fd90ce6b831aa81be7d413832cb072a15d23baa3650a7a8d2fc8c662f4b563d970152c502b41dd8bc" },
                { "lv", "c673da291b0558f55bdf830faa8c1592495980158c2b25ab42f5092c7b0a50b90548c36a3bfe0c3ef069533e998855b78f9c59492d7611c364d0bc4134a508a7" },
                { "mk", "3754fbd79abf2ac0c3e42450ad5f18e4d82bbbe4c808997f4c1eebbe0b827fa24217e5783c7ba1562b9a2c1ed6c2fdbeb300890488037827b4396fd10f72c209" },
                { "mr", "487fd0e0c5216596afc62cdf91142c20f02ac02358e91c6c7595711afcb8aa95cd4cfaf97def5588c0f9c652e51865dcd6fe648964cde00e4c3e923106896735" },
                { "ms", "4a40a39ee7e2fc6835a0da9a8fb2aa628b839be2071465bc7bdd427f2bcdabaee73856d2728c800210e30a436689e5a0beabface9012c4fac0b10d443baddc75" },
                { "my", "77ceaf33a01182ddc6fae4ea9e9be17398fc243ecd7b97ede1a8a6df7ae45125659fc94bb90a40f5efb39f2b4d6ac977b3b7a4e3e5f703e93a1da6def0fdf838" },
                { "nb-NO", "2f59833998657f3a82a9ab367b5ca5cdd0d9d61f440ab8a92e758bcfc0525ba4f026915f3051340a0eb012f48976acfeed5de8e26e2492f9fe4a1bdd123231da" },
                { "ne-NP", "f34f025d441d8523e465ec7eb8a4fcc2e6ba3de10028e56297844a61005431ae7a3044c82be76605bbe930c8b3d6910d39fde044889dc942305624a9bca10ae4" },
                { "nl", "42ec34611ec94d55c9cd8d9ccd281de76cfe4bf05dfc1782c9937754e5473bc5a94932fbdaed98d92e60ef16ae7c43c2d6753f7897944550a696dc7edc381eae" },
                { "nn-NO", "3ee6a69b5c8aaaeadfbdc77da387ec7359a95f86fd5eee3a88273baa2e731b34a286639fd1a534833170786fc3cc74f9021eb36c7755574d06fdd3269f887d41" },
                { "oc", "5196109f1db9f6c9998b6e157ecfe101578b99fd1a736227697676288d03d3f72554734f214e9f7fe4e87b5160443f89916778510fa1b025a6a72e459b9329e0" },
                { "pa-IN", "d080fdd3c8f96257ef38bb62a471e0746426ed5e6fc1a4a72739a0cd45899e0a728c510eb60c42657e11f27ee12fb037289aeb47c89f5a755fc7f4b2541e4701" },
                { "pl", "9f7f2ad2068b51bb367482af54f7dd665e582115d92fb3ed38f8825fe210cd36a29b60f67807ddd0cf4141ac9f10a9b44f04a9b376ab75c01c8041ec18896e27" },
                { "pt-BR", "aa78b6b0dceb6102589ebf67cae2b679a7273343f919506940e880f46989029671240be4bc8cb32c91df5992d43e129c6d48c752c43f6810dcc09d2bc6981252" },
                { "pt-PT", "b203c390cd228c139707643e9b5f9923a01daf3ffd4937047cfc931f0df24034808d26511d49d95785907d09869e7622c34aba7d44e443be4cca10973f7c4e04" },
                { "rm", "f3d2d346f17ecb97e658ae27e77aa749cf66f733f1fafe999e1728501cd3ef1a0b8a01366db1b88ab542219e1426c7504ec5e996fb43569760b5daaba9ac1c44" },
                { "ro", "1ed8e614ecb4b457aa7bd89b47df12c837ad8b9c4bb30d2d68f6760966a57b81751572b6bb5c173aff88a6ad63b36d86fca05d43ba0ced6eb1dc94278cf3a2ae" },
                { "ru", "6d43dada67ad2a6b11d929082e9c5a4f16783b10db8ff73e479f323716e67875093f23bad300a76d76fabb73a1efcc0534ae4862fb5e68c614c0a3b5190c29a4" },
                { "sat", "6ef9eca54125a72d3c1f8550051cfe1080e52390f5b992034fa7f71996c9c776f3573ec8c99ea7ff8981f81bdf670eb4e862b0165a547d5e9942b10dd3e1a552" },
                { "sc", "3431569cd4dc3dabc615ec8d0e8ddb2d4939e4313d804a4935abb1bf0eb80e45458c537be29f3ffaae6a28f29dfada7e79d64d200c502cfd32eee847e6915a70" },
                { "sco", "3ebf7de35abd9db68c592677ca082f693ac2b0806a831476088ab2f32144d70a0d1b4497f7150a7d9bce5e6354360547c5eeb587d238387313cd3231f3e5871b" },
                { "si", "5e8e9e49c3fdc1bb1ca467c8cf55faf20d81bdb7d268f75f133ac28469e5c10b793177d88ff283b6584f610838bebf1caf13afeb910d3556553e84b76c65bfc2" },
                { "sk", "7c7008bd0c339eec78091ad83b248ac77fa19e32b38360e07589d67aae7a87a551a0858209bf2ee57f2bb8f9139b78e8d894dbe7aead416e12c722112e5cb621" },
                { "sl", "86bb1552bb54c570c443aafc4d25e82c841a662367cc171fc15cd756a3f72fa8e0cf8de769f8da8d40b933d17eddfbef6655d97dba96d262a9fc96e59db2b9fc" },
                { "son", "91ea93891d542a99c1777829192c4b960f961b84df3a1773a4ec8da95a731faac8b68d03027b0feb154cf6a801485ec9feee4735ac44fdb5cd6af1b177ea04dc" },
                { "sq", "b997ae077734e9886d2e672b3788b661166d1a690cf99c075c4075c06177c9929447636671199bec966314703c0255283254e5e97c7e071a9f67297c738cd8ae" },
                { "sr", "e1ea1e91577e7ac82c3dbb5e77d10b98ee2606f4160f6994fca976e60454400e0242a46a3eb98f43699e422ee5307d007f41a16683d823d66a49b7cc8ced4494" },
                { "sv-SE", "6b58f7c9035960c5370148f38f6e576d1dc937f322d74f1f727dc36c0e8a976229645764e785696ed36ccce8b9097d133f159da2c5ca4b5941bb9d53733b6f6d" },
                { "szl", "09fdd523f664c4670e38a308a86aeccb9ee75c93f6c10da9c9c37aed871147c48af4ffb68143385fe6804e9e2a4bc31281958ee6e6f592943ba7d05464302fe6" },
                { "ta", "156f17eafb049b3e5a69f49046fc3f96ce711f2a312a62913eb41eb2e80449b95a11065088d8fad88836c5c580333b76e0d8d7816a1a5a10a1997c662c224160" },
                { "te", "4a28f110b8e8ce5d841b88c00904fe2262e039c44b092a2d00010c04e8d98cc86e49d8f4c3d291433bcf6672dd0d2ab0ab4633fbd7e876c2066fb2d79406ba80" },
                { "tg", "517dd901d312d95fdc6d299d049acab800432780947a133302343c20ad6e04b4b90bfa5102b5cea46f5784e962532d6c662d538ed8952dce0488fccdd880000f" },
                { "th", "bf7e56a688e92932d59b13e664736d651fc6b8bb747bc7e639ece1385ecbf73fb341f176593bedd3af4655da1f696acdd3350729a28ed28b540f6d72b53aed5f" },
                { "tl", "b6d34ab506773c0d66ec31d8a910e05db0381a218dbaecd742de8646dc35d8b4cf7b61789275bc5d94178fe8f058278cc64f28aeb942a2c59351081c02e1d08d" },
                { "tr", "458d6ae5998361f4e1282d3569d7bbc6dc4cea2985d091acc6c1420a880861cdaf54c68a73eecbe06a3e009621bd4a2a2781c94402f2d37d71163d28169a35ea" },
                { "trs", "67bdc19d553f67efcdb2646bff2423d328c0aa4be5b2444760121e9f24c63260bda8b3f9c900858b1491ea4ad5cc62a94c3ff5e0596467737d31e1ad718a64fc" },
                { "uk", "5eeb2d23b976cfc42d8bdd525d0e658b752c5bf35a12e6d35b6ae22d05a708460a6180429b55c66691875d5ee89cab6e9d60d7d1f2ee0964478ed16fffcd9bcc" },
                { "ur", "f053f51fca89e1501d1311af66d58a85efa755768bd4bf68d79369cb4a68232bb31d9b73063fc271a1a79971c8c55aa6458b46e3c1eef7ce380b12d672c080f0" },
                { "uz", "e8f7247111aad580500a599d77162afb60e5789d2688e3f09d6bdcd2544ce7f1ef49cc7c46a6c4a57998b897c1c7ed03ee2aa482554abe6ea52cc3dbd2596cc3" },
                { "vi", "5be3eb28b41ff6f753615a0354d67d32ddcbc2950c929279290ad7337dceaf4ea9ed2e449856fee75701bcee3f43b04869d2960c98de0b175044ee1a9fc3b979" },
                { "xh", "cb7599ecb089f78d8c5da9ce5a1fed2af5792ffb16e74ff93bf2c23302d3abf21686d2137b482b495fa95343fec81cee4ae0afddda995bc11599f6fc35b4ccc3" },
                { "zh-CN", "3e4c683a15869b4b2894e998c8315342e13169d30ba7aee6e946920b8b209840bc83cd80c36ce4c1b45afa42f3ab2e2c4404702e10f87002c9c4ed886c976400" },
                { "zh-TW", "c2f6d91ce325ce41ee524c9517224620cc913e570942e47deedd5bdee9ead2597a42fc91bb168e12b36822032e5b3544ab7eccb340870670c96e0176dba7c2cf" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
