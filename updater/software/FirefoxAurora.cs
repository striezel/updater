﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "139.0b10";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a40f3b7dba845472f4055d2b6e131c424de1a368f84085bce9d4a0511b664e6f5a0ab6cd7607933f045b24df93c7b7e2409f67c0d209e88d75b95d36d1f8ca58" },
                { "af", "db71e7d931d3b2f640357aa3854788601c3d5d13ac56c7c86eaca2639fcba3fe1ff4a7b9408ef216a1593d73445b516948a60935c1a9500334037db3385c71d4" },
                { "an", "d2a2d164f3a08cf2043205fa70050d82b1de1d88d53ab7ef5fb4df6e49f901d68ea0c24ed17ff8a2cf4716cb65494fab9581a9a28c67df7ec4ba29318e217e9f" },
                { "ar", "56bd5fca2d14860bbf0182eb742271f957fda0e0a0bd15546e4bed9749d2a1d83800d3ae4105b94b57ae561c359773c6bb17d6fef7a3aeaef9e7fd187595df22" },
                { "ast", "06414e3abe850affc371399e6a82f2a5b1d4380d059d137e4b628c22836bfd1a63882fcedf33ff8f99b954d8e0ac41f9f9933e53dc26381613baf8f069b045b3" },
                { "az", "12f9673d981d6eca7a63134f4e284cdc90a697213051ecefa7a91b4fc2fcbcd48efdb2854992b7599af9fc7b88e8eb89fec9acb537346a05776a95d8d44bc6ed" },
                { "be", "6e0bc410c723778352233ccdefda6490ce766913ac4feea9e70bd6f862cc4c18c1da88d56620e36ee7beed729e89b77ca8ac7a302a8a146108bcd059be3fd29e" },
                { "bg", "3cd62f7824599995db7d94161e40ac82db71d4c56e9c21bf43752c03076698649012580cf7eaba351bf0d3ce5eea4aeb67a83fb6b6e86cc2bb2cb5a164b81372" },
                { "bn", "8f6aa4b12c9d08528ae7adeac8397c04507f65814e84c5bc45ab6dee35894162000aeae39dd2fcb917c6c75566cd75dc9cf3a599e3d87f4a8721e8946edc5d29" },
                { "br", "69eec8b8fb6f8bffb67fabc987e79405497127a1f63d3545c2ebe5785496e9f6c9d5a1b9462f3830135ba329a2facbafec8c5b528d9555dafc8788afd52869cf" },
                { "bs", "7779a4986eaecdece918c4508b550ea793f100674ad8996145e2351a9554777c9f29ac5b05cf0e33494c2a79f185648a594861827474e8635bfc5e8306234b77" },
                { "ca", "536c2e234f46d7052d63859fba35a85a26df6cbff231efec7d5a7217a68c7d0d4daf18a5a60e391e655ff5964772ce87d5677ec2fd52a29005456cbee107b0da" },
                { "cak", "485b1fa7ca36c1257b9af0121cdcd935bbd69eb8476f56488c60a70e77ce9c876b2005dd74f81a449125e35a532a48094494aded6e2ac16c00254187c7115310" },
                { "cs", "990c9dba0c9c089972fb666feaa17b967253f17ff136bba7e217438070a6370c9cea173458e4807e5e27fb9cf3d65405e4ae1de0860bfd2d9e4081c7e2ed01a2" },
                { "cy", "1b832772c7d2bdb65f761d804d735e0b4c1e56893e1f08ff41076b4d7ae63b8a51c708e0198220df3426a1aee5b0d1924a9bbd1d429e3c77ce293f258145782f" },
                { "da", "229538623438e189643427965a9498134d320b18d75cc4ef507417ae0948a9a17a1d48ff6d94a3f925729fa633f5cd96f9253d4131eaaca61f75af2d5c1ae5c0" },
                { "de", "c38cbb00fd8a8b1ace111686ffa667cfb3399fef6aaf8f2ba93f92422ff65925242d23ced0d6b54c768f084844ff73bab0b73ac1cf63643d5f0000be6752e67f" },
                { "dsb", "0bc3de31f4db3b46f1636b98112f56651dbebf6e41536bb5fb79189b6eaab785abf561971f53c1701191757f7b385951cccfe63dffaa1c03ee542835097ddf8f" },
                { "el", "de75f83bf2aee9ec123fa9de4b5d81b004844d785d123274d5e9b95e1ed21ce7f7f187dd41a2359321e69d3e9b47ea2b2c3451427786ded7d91ab64eb8211cac" },
                { "en-CA", "d410c830a8a73a64eda28820c1aee5a115633a1ca6c1c5fde9791e292ccccf8da74d16fd731b46d13bdbfb6065fc297e1efaa838026ba5e74fbdc3f8d93b23fe" },
                { "en-GB", "b9e0995b9fcad32fbb17fa70876a7729b4806fef3e2c4e867e8f60794cca63034629b482c913c5c1b2bd92ddb57c094096d7893c7b55012d3542ce8b25c7211a" },
                { "en-US", "97392bf17de61cce57aa96e83ae56d7ab69e98c7b7f1e6bf826cf501c23d73aefed9fb33f33fd12cf0e4a5650cd7da13ccb0a7deca38a5896b0499d77f191ae4" },
                { "eo", "ef840d7d7bdc339f5bc5eca3ac17429f871456df0c9b863c2bb32bcbb9840eda391fdbaff059286d9919601ff48c31eb4bef65e07eac867a48f048368b97a316" },
                { "es-AR", "9ee9e4aecf743e36bd9fd401a511ab6f829bf10c9393f148f775e87a858b6d82e0d71cb5cd72fc0569b1f64946d943a3efc41b6f3b900f46ae9ef0e13fe8d2cb" },
                { "es-CL", "198704186969064d1e886dfb94cec6cb300a6e152443ee2ca9f2b86a7c585ae0bfdcbc85cf1f2daffd5adcb1ec95484a8c9206b69df6641bad4c8922f9114a48" },
                { "es-ES", "a56797a943325d4b21474b3c165f253e23967576f40ee9fb11ca97855a14ca7370e88e882f2bb5261752900a7c359717bd0e8abcb2473cceb91f38f165fc66bc" },
                { "es-MX", "35d15cfd4078d0cf189ebae3ec9d2beadd2e3d53c83c901be585741926646098ad33730c7e8d7b521e76aed4900462b518bae6e1ede2594ca4b1ebf31ed460a5" },
                { "et", "2b2c17dfe82d7ed64c00b66a66f02271e44b8a1aee537c2c5274d7588c88080aa7bf8ade73a0e845c107604ce4d7868ab2db94a2bb9c480adc3230d2d5d1c8b7" },
                { "eu", "e9f85d80b5c554f77350d8079b759ece439bf579b463736fac22f67b2ce898e310ab3ed68abe03009c0950c49df3c20ff9627527b0900f6ac776c66472e87a35" },
                { "fa", "dfe2f7572d8f911f630e38b1c2429ca653466115bbbb689f5387c65c8caa04f8ecb1ef7460df5b514574984882c06952b9d6052c7b6d4df21483d4455f1cd5b5" },
                { "ff", "243ac2358e013555d5c6e0800303e162a0c696af74a676428dfae2994d5c357b65948dfd01eb82450b11b02395300940e7fd7e0eef0231ef4ba3b3ef2ac01862" },
                { "fi", "d9ab118e647bc92523a03707ba0f278ca347cdb75c97b051fc122b6fba1c04192d7988b9bbbf6896a0b9bcfba9a7ad27c54b9ccd00fc39493f37c3948838b1c3" },
                { "fr", "bf5498127836b140264a1ea8185b82a3160ce1b608cd79084f5fb82a9d0e845533575acf3b72b7e6113a319a9e5b29e7a2a93953d68888e18ca56e81f04f8a71" },
                { "fur", "2ff3e7c634820bdf0abf09109f5ab38006e26e6418ab8e5cb1b356e1b4912937a794f7fad175289287de36c22d2c124564ee2357f16a54afa949d6d144ab2a29" },
                { "fy-NL", "ba9cd36c4078aa65f07a8bd68e5964f8d6a3e00398ec53270705a4f07ed8e5781d94be82d642fe8dd253ac69f0532be56b207c1c40a7e8760a00658e366c1069" },
                { "ga-IE", "26187bdd271a8d2a0463b45b808e219ae32537e6483afb0dc167a46ae0cdee48a913d0d38698b00b696f2e0418e9ca264ea8bcb235f0f21af562e52a43793bb7" },
                { "gd", "c81e246b992f4a762d2b569f47741e78d32937e2c8ab9553c6a042fa934253336d3fd5d63d42b43b1ded22f0820262bae56928dacb115dcd7d54feb789e7d510" },
                { "gl", "73149e5e4a25be939bbbf4fece4bc6c488f27f3ab86b4b0706ad8688dc288223da30ab705894945d6f1b2a0b84f5d369ed20f8bc9805b0022ce4d708e28fd933" },
                { "gn", "53311b99c8abe3ae4031180990f253e86097f2d39790f16e9652132b6359f0b4b2bd8cfe3c65d5784104748ea629d58dc8150cd72955c69f533e5b06e48a9eaa" },
                { "gu-IN", "acf424994ac274f28755593b9ff2c3420b81c0eda904115556fbc12b1866fac18c6b22da9bc41e7099ebfd834d7a7839e3a75d923b09830765165478cd9678d7" },
                { "he", "909bcd9adf1d9a222eca823ccadc5c267ffd53a6fdc077aa7e4e18fe6538e369bb74d2b0f9680e1183431ef703d19f546d97f98ebd0ac98547a7f09a5213ffa8" },
                { "hi-IN", "8fc31e5828127948c69b4a167b0a85b7bc3d33d3e8e12c26743d2ce0bae37c9495b9e610adc7f7cad02e712ac4d8689b4bf6a313b8acf7719196f3a516358175" },
                { "hr", "fed567100917fa37924c239f9916862a2f4023083469c54c124763475cbeef407d56a471cfe4f0f38b553e6ab6a3644d8f77e2a3c0522854095c201589d3e620" },
                { "hsb", "0ec6132bdf32b23e1413ea4027821b5b0852edad57a3abf481106ef374109f28019ba44d01a50542eb68213cf6be5243802d265d576c14e391fb0777069cf787" },
                { "hu", "eb1c76d979da2006d99c697e9924e5272cd694d021556ab0b68c5faf8e46120dd51702d183eb937c42a6146c061d5601d860a69fe135050cabce803d8c59f7a3" },
                { "hy-AM", "8b083ce4a6943e399587ab8bead6230fca8d5d9ee77af044b131503e2861ac4df2c4c1fbae136cc92441fd4da82f89161206530a25054d63c0b42e7b853a451e" },
                { "ia", "6f90769a505d2e6da27a1238ceb0c4b7856e9fc124d97590149cd463dc010731d4ec579573424c34cc0fc4b7527dc11110bcd9353bc8b3e40d022c7c84215c60" },
                { "id", "9deb7de3a22d2b0b68a29f9a75de84a1aeed9db8777191e842040fa80296f700edae90c3da1ef70ac9c60295f3330b0a903a58c4364a47e24e630c64e4d35588" },
                { "is", "aea7529137ddfdaf4db9f4a498a9b5b8b1d1abbddc5fba53ab0c98198712b9c17aebc9f14d0fbbe90ce494071c5dff8690bedc8aa10481a619dcf8ad94938360" },
                { "it", "238b9f5adbbb45eaae2cb1a5ac9757b3407e071f15823759f0440e67fb87b9c02dc8f8c48d0d56769d3c83a80a140944bec423e7a5801231dc912c428e42930f" },
                { "ja", "36d153979766ebb528c2574d029dac4f7fd96df26f6cea404b0baaab0dab23229d83c95fffc8f2b5aa8cab815ca750a78a1215150ec62978f5eb314d6edcdb2a" },
                { "ka", "844f9f94e39eb7e094d88fd7c76d29048a64d123830de9eab2b79c6190d2748705f05781b64ed3b047ec076452229b25002aefd2c01423a0c952fda4111ef92e" },
                { "kab", "89990818b6a91f9332adabbbbd074df3a9656331d63012ee17751b8d920a08a5ca838b9e44fa59c444e9fa5ec13d8091f17581c94e110d13571a3c57ce9ae796" },
                { "kk", "c4dc468996e897b055ba7b90a761083806ce33ff8a849031bd532c17537416f6ef332c0c16a59e51e2cde470125e514c82bf9438a00e226394cef0488e831d7f" },
                { "km", "9ceff82c59251daa85c38181d2c30fb2c8c60fa955e460edf5d5cfd10093d34aac96acd39ab70991622d826bb543fdb4ef426fd05899dbe8090c05eae49150f1" },
                { "kn", "c5c775072b69a97617fc6e31fd15d5c37231abc944e5924ce0bc2365226491550758f7a601dd2ac5ba937db80883c4a7e1d1eff841de99a73a1a48384018f77c" },
                { "ko", "ae5115f1ebba95141ca8191803ac973ede6312cf53be33a685e1dac7dee92bd245b851dbb257bcb4528ef18debeeaf268a876c8bb24be6800fb3cfa29f685009" },
                { "lij", "6c322a8b830912cb796310b3223db19673c1b16d28e1e16feb6ca3851a879a739101c441569483b3b532c8d2e919a683082457332c34f83d7d89e93f1d66c264" },
                { "lt", "9f06062ce1e495931d79886c4ce65ad578d84744032d649f9b0712d667437a29ba351fa77a697b1bd14fffa72e87fdf6804d73df750649cd054447f1626703a8" },
                { "lv", "8fe87a80884c51ad3facc0898d18d0d9435d58b7311b9d82c5646bd19fa55c5bda9d438621ea96708e4482314005f48f7753e28d8a86c3cacc35781490786fea" },
                { "mk", "2a295b0dc3dee5f1a78f5ef3ee9d25c891c382e08739f6c51703086b57e9633eb9c887644ba08e55ced77f81842834f22461a859a280f335bdf493b6c14a6595" },
                { "mr", "91f08fcfbfb45eafd15b85f314afc879e8c2b33318c342ee18c179abeeacc59327f8f2cc6c1f4b535cfafaec76ffb0808a6b69c671e6c247f7e13cae0d5a036e" },
                { "ms", "afaa61b6498a66b1a5c0e0a59774539b33deaa4a578d0e41a1d4e6711e5f43a806307b56107ff80b3569cd56af4a586592cd772fdd577964a0e5881fb47aeb91" },
                { "my", "19ed81ba6f5e043c64b5d836d2bd9140155a75fdc2ba5f66383413028bc0a95b3479fc00391e811e4f8b8c9add5582bba96ef37644e4a7327249ab8abedff9dc" },
                { "nb-NO", "e7a67fccbc8f4b1eaff05ab072bb29c7f55d4c8cdddcd7e0ce6c40560ce4f6c75999c80d9b06d1b6f77a0914c4398c51ff79c5012c96d327dfa0a22481e828f5" },
                { "ne-NP", "8f533c81c1e1a8cda05e0582c619c16d4f443fb36fda5c8f7853ea6ee7f0646df477e6ae8309d94ee56269030f1647f8320f02e9b5729ab5f4b42a0096cf3d1a" },
                { "nl", "4c907f15976253c709acbd69dcfbc5db3d65004801a5cb99ef6a5184b1441379100c66d9c9a5033e0e165f91d3088210725288e44e4f162fe8f9690ba1fd1fcc" },
                { "nn-NO", "45fee17f1972a84ac10f055a28bef8a716c39a0437c9b0156706b9a964f2fc5796551c35b8012fa08dde0b8ac97ce6f9bfea9653f6563d018e840aa6c8ceb812" },
                { "oc", "bfbf730f325dc05030b50db65116e1a4806607be3c4fc8f06a2f1a511618353b47652c5eb8b683ad147ef01d73bef196ce0b4a9f7922c5af1112321bc1e64955" },
                { "pa-IN", "aed80afd0b2292fdb60e16cd48cb1b6609ed78a8faab5a47a267d670ee2d39a8fea61c5613a7307b74fe2a008cb5863e385e6c2c4360fd4c3a4a3a7c695dcd27" },
                { "pl", "bc039b4df0b9efa0dbe9017486014cc0f2872cb08c85e1512c5cd63743ce0822a946dff894355ba7ecfc518224b64d415a4e2c1224be797cae67e0ce455576b6" },
                { "pt-BR", "3362ce68a7932d73aab9d91a8503d9be33216d892fc158610b448cfdc12da35140376b2074bae17761df506b6642048eb50ae35ed652c51ff758a0e88a3c0a8c" },
                { "pt-PT", "cd8c26e190b1456170b5a1467fe910794288f4dd6322c393d5e635211ccc3e91237926ebd361a072c2e0b216c940a2089989f5d5ad2e04999fd72938006686f9" },
                { "rm", "2c75357049cd516537e7f8e350797d691205afa94c769e2ea31430617bd3b02695192ebdb283b16ac69cda9a4b9ad308f1935f941e99dc188ad79e152ce78de9" },
                { "ro", "e7f1c7cb01f7ac971ebb42264ba86e52cb5a10f2636a036d9310eb06ed792bec32bcf69c41adfb38e6d34acd47573e43e4ec1c20ee051cdb5561b4075f4f5cb5" },
                { "ru", "9bc6edca947b3c4db45880f4fcdadf82e5a7778c1547d440dc7acaf5c2d6ddd19da4b0edc0516aa53e1f034c5a1767191c85cac725cfd5921b5f97f7ba9ec8df" },
                { "sat", "84455f9177501e8c13b4084c4df16f0628e0017b2fbbaa1265d9cd2d0636375d493beb7e5b4517cb6e2888fea8c4f5ea052bf466ae67c2ab1a82550e179d9c37" },
                { "sc", "e6548a35f901a09fade273e04ebb1c69919dbd568d3c620efdfd0cddaf04660d11c289a993d21db789a0b8ae69a9e032b3c6f92c0bcd3cd10df97fd165509ba7" },
                { "sco", "4e5fab6246e3cf1293eb9b900e67a516022122ab41bda65701c4e6f4ad49bbf6698a094ec2078db2d457cd237132c308252fd24a8c803de63880f7dab2fb0571" },
                { "si", "9655b8279068c651cc1ecc25bc1a3bb6f3bf78cdcce1a26e9566e111129c1efee59825ffeb94cc500311739266a998208019526a2fb2ddb772171625501a2b19" },
                { "sk", "286bfd6b5129d0ee20f258011d2d8851ac7d3de09208c6414caa70f76823d725ff0d4777b3f323b14610e563cf324602a63c5af73177b81b4b30f2034d15f106" },
                { "skr", "803f91953628e49306db8aa711311694418b5148a154f6fcd7fac7c10515c92f762017f456e52620ab68b1e502e54c90f874649679aca59a674425ddee0e1353" },
                { "sl", "b252b92b7ece06a390ad0c365f856ef9cd31ce9d7b3794bd7890ff438e646450f64a90e30854d51c9f42676eb7cb04601e856369e6bbcbd6ca50fe00c753d380" },
                { "son", "eeb814dc0fe58fc2de5127a4c694cd7c11bf256e7ecb7ea8055085467ae67279585e25a39d2edb8eeb6ffa0a607a7727b719b8eb5f7399485449f4c58531fbba" },
                { "sq", "e5fee1d22bf030320231f79c4d0a741a394d04faa733ca9ec34cd21824b7ec8d270e1fe55bca7104e5f0a0c2365939119f72ddbafb1f6ff1604be146959dbffd" },
                { "sr", "02d16374967c5533aeb12e4b2df8eec3eb0547b139d1a413af3d69e57494632f93a5b7729d0d28e5f2d3bdfb39a625ab02291f198a7939c75e39290005bc8d42" },
                { "sv-SE", "ab8f99766487900616a5eb2f29e5115b944350e6725bba453b1d0eb2b8600be27a14dcd663b925073f373e9ced4e99b682cb2af44cd6434fcaa115ce976c58f6" },
                { "szl", "539b31b48e3fc4f522e8dc736af52fa2a44d641ab218b2836429748a42bf190ad990b3f6996b28e9961e959e0a41a5a458298380c2632e96d62608618b07d231" },
                { "ta", "508ae7683df755a46f2347870a5339e55928c2432f161c8800f19a370580f741eeb2f6fcb69fa065f9a194cc916209865f14e7e8c8ac4027b0792084fac67006" },
                { "te", "822f08e797a7cfc73e6a87bf8f46aab01944f3c2715e9236f8e61b9091781faac5c8f193d625f8033f89f70f82844e37ea838a116ab06dff6c5cc5f93985888a" },
                { "tg", "d24180b3937827552669c2c2f55091f7d483ab51a3964fea90f379edf03c5fe6ebb85f17d3d3aa870a1cef4fd88fe7066d830248428994482ab6647aa4bbd1eb" },
                { "th", "2e5b31c83f9836daab7c0e94d01e08ad9d40dc7f7c558bc580b677ba0c30e817bfdda1de2bbbdb6ae0859b8f073a22f24c821f4485d8440b7fa9bc28402c7220" },
                { "tl", "caee02003e945f5060ef9b630d7d9089e8fc3f06580eed43f3c9dd0d91b75c9bba241becee44f469c470a176eb4ffa6c6aa32e67df80b886e909852d5c8ab1ac" },
                { "tr", "057a36e1ae60f922e1709b9be16be483caa463ebecbf046198668370582950ae012ec2697d6fa1d5a6ebe3156b0cd1f4b4adf97c4363cc769f6b33c003a013f9" },
                { "trs", "6fc94e33f5e2f5de35a51ca969f648e02d897fa04dac76536120fcd4b7ff11b03fbb54d3867c675c2b5c9ace3e1d38acc976ea3ab40fb1325c7f130aa1d44435" },
                { "uk", "6cf3b9dbc7f4caa72b6d4312825449f47e7ab4c1f1cfb56f920833ed0ad71f2c3ebff6022e22a334cf1895f72ac60340d902394fce3bf6fb9c45aba4b33267e7" },
                { "ur", "c40334b010fce30c9dacaff090bd328da4002e1b8e10b7030c0008679a542bcc3e55ef3c5ff2689ba4a69a300ecd3012d23fbe85a3ca47a27d7122cb79f7536c" },
                { "uz", "1ac04574ee49c4a2910bc83db49f27f628105fc4602e512cd6cb6a41cbd7a8e85256391d641f6f1fac87b7f1c7f46b8fb887e8d9bf684b7bb99b220cc0f48fc7" },
                { "vi", "b00c20455ef2cf7126ce7c07d1c33e4151038da18877ef02b86fbb2bb7cb658e9dc06a932f4f35d4433e15a3f9b3f9e1c35c0a00cb962acd5e2807cbd4dbd008" },
                { "xh", "33ade4d44478612c37ac57f51af9683d4a3307069d6bd8ad29f11ad107a79d5514d1735232d04aa18aee9a78fe46795c564e62727b814d84e1abfad1a085a2c7" },
                { "zh-CN", "472b47862a0a3ab6fad2753307fa3bd64c101deef6377b2ca53142b6c2be110c25f04c003d0fd7b5f88b468b741533488d802a5996cec949d460f2b66b98c998" },
                { "zh-TW", "84d7e0cbb8e8e6567f2ca06dcc1f0aa688fc1f53d3c357d074c53f9ea9d2f4a201c1377740c3488413de1168d55546bcb661565472dd4d67eb905c3bceae4371" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "254e642a4ff65a88d152d2232c46128a4aac2441fc56b3fd714b4dd7eea7788f4eaf9d4d06ac53e34dd89bb28774fc148f0d3b7c7ba8261e92a0e6c5d23aeeee" },
                { "af", "6ad36ab5bbbe2cda640cb845b20fbe4435ac46b3c0b65568c9eed438fe26419f20b0972213b8a58c0dd5b87591f3a0bedaf37a6b4a90a31dd37b618fa09da422" },
                { "an", "f9ceb79bdbdd6cc15cd1e3ff2f5091fc11825287fba207415522b2b9aac985af5f5f830820ecab68cf3af5abd335285e85acc4e5bec96a72844987e43e561df3" },
                { "ar", "483ac7c8b312c1aa9c16ea74752d553262d9bedaaa42a284074509ed7e2f8b40b13778bc2e962f9ba73f86718a2f4d8d9eb3af70e35b9a699ada8ab2cc9a054f" },
                { "ast", "8845e7efdd26ccb962bbff24f4e6a6cd76d731a9b583210e987cf8625cb4fc8cab9003eb9421a8074f3f597d05130a2e68658c574c5c85a56ecce56b679f2da9" },
                { "az", "47264b633d71e06a264cb1d89cc42a9a9be692602c020c3fd61ced7ef4138d03025c8e40609ca76b1f2ebbb9a15fe7b7a8b38da70766f19f20576a91f1005c66" },
                { "be", "d0ddf6deb04a55687570124069998c4f254e10acc5aaf1406d16682b6c030047f0762d93ebb6d3160ad6d69349121a066bb2cc8c98b08e62fb993d77279b5129" },
                { "bg", "a34844a8c94f62ce2ed7e7220c154685df38b62fa20d8f0a4d07f07bebda5cecaadcebfdbc78a965c182c5283f2fe210bb6fa9c10b487ce4c97183514df9fac6" },
                { "bn", "e8eb977c0916b6e50e5a89c2c7ee62e420f08ef462b28eba52cc75aefdaa83589a6d98371374c028cda2c235790720d03214cfde1d5bd1d61394e11ffd1ca726" },
                { "br", "5da4d8e132ff6eedda1f09c7d72282d8e31a27b6c48489a5fc1209d4a1bffb302c106bda728f501a38b977088fcda8f869ba0fd6913a3ca0c2170fca8edace63" },
                { "bs", "ec729369200dc6a61b0671c723ba63d153d0183b6faec91c38cb7ed5a666fa0ab92c5b3003b5a9dcc6256fcb6864fe0944b60add6c5d53be9c44eadf7472eda0" },
                { "ca", "2bfa8b921438fabf2bad3a10432fa01a3f9ee8a6cded39714f7b27c9fb73f5564723d21f08c1d5af1e12e21fb103ed87de729c9f104f02791b5307059bae4a43" },
                { "cak", "edc2230c685824624a4193b60482e7fba64a73677d44bdbb99690e5123e9fb7ce60b0ad699cd9542b29a00caf4a084ffa34a018d8c3537fe4d5ef7525070f1cf" },
                { "cs", "1961b0ad110603cfdab369a7835de8f69298f219f966167432c57339cba4fb821e0971c9bbf0a5a736c42ae04632a2dafbe9ba7d9d875198f7d744a351d1ef49" },
                { "cy", "ec9feac09b6a6d4ec383c1d4f91e9740262dc347f80ce0993bbbc24e09a245a168063bc7f753d076c9fc4779fb7111a542fe82d67ad3cdc42727e77e4341dace" },
                { "da", "78d9fa20925792cb87ab5b97a77d66fbf8d75378a0014397bb3f0709b2bbfd90c682caeb415d87b13066d8603e98ca22b25cb26965409cdd4eac238cd897a5d1" },
                { "de", "3095740533ff9c0408fba70929296d26a39eb1037893bb95eb78a4422b3f9dfca83e65c3943b086b6d95fb67ca5d4348284345ff032edcb026fe9b51713c23d3" },
                { "dsb", "391925ee70228de803df5b2af62df443ef7088ab3b9fb71baa392533de6fdb8beadbdf7a113c055500ebd1fe380395488b9ad4b2fefbfe496893a4bd78b367fc" },
                { "el", "834aec5c6808860fba09cb2116b0974dcdc17bd5bba0f2edda815875650f39a5c517be381265d3f738f63a4c82364bf424c3d4378e199842fc2e63c8f9aa9d8c" },
                { "en-CA", "ab2f7a7be55577026d0c9935709aa96f01f6ab4870d4ecf7252297b13c1c9bdf4996013fc53862599490fce7eac4b30ed437809d875cb0649b3b873e1888c2ad" },
                { "en-GB", "acec647bbd119356dee532c7bff08ab8bb78a709f0aaeac4de9c372f999f787bb77bfe7cb9c6e1d89b6d920766ba23dab946d07cbff2b2e23e578ca988228f4a" },
                { "en-US", "30a9240575553796537d5239486b377032222fa5191e3060153c4f66b4e3ec0b4d4f14f3f0267ec795cb177d64bbf9d549fafedf603cd30aefffa3b2dd196474" },
                { "eo", "b90db4b12a0deaf1510b9daf558ca36a08f541cbe6a4020465d235d7e7adaa268e7f058203e4c18a48768180fdd405606c7a0b4e56ec6509ebb674fe8362c4d5" },
                { "es-AR", "fff9f244526057e72ef6fac400ba012cc7d7e75d590225e3e071b1011f1fc698cd90c7172aef52a31113f125c120cfc1497f84939c31d30deb3394258cc7b26f" },
                { "es-CL", "0e2095410cfc9717307b36d7e360489c29b72776178334c72373386abf870d75ee9436c5c32a5c149cb2ac512d7d624e41965e950da6363a02ec4c88462af4dc" },
                { "es-ES", "75785bd66a67799ac874e082650dab7151ca3ed00c104b5c1b4166b36487047ed7b0117136014e661f1ade391f8ee0877ed1809a0dbacd06a955f9652db376b1" },
                { "es-MX", "81736f2863f9aeeb8615aff8ea9a3d75a8c15af2c3692a0cacca46105777545365da744278a29729dfed27c0cd72fcd4636f2bdc3abc07c07f9262a9eaff5e45" },
                { "et", "9904e055157161e12798245c3629871090bd63227d31f83328f03c02e42efe4362f3069bda253e2121621ab2e29eb8bee914244ce7f0a222efa36149cc1ab5a6" },
                { "eu", "ccfb0a9b53f1a75b191fa9282e50ba0315269e799df76d92d979dcbd1315543382a662ec6f8fc6f226c056b4fe1fb1c1b305e2ca75863bc3b5a6e370fc04c68f" },
                { "fa", "d09952b874eb2634fa22c92af486b06ed1ce584c7bca4a86b4240ac038345775f757d3fb2ef3bc10b2071d6bc4f7c592a67aaac9d0d23627fab14d1ae161b9c9" },
                { "ff", "dea1342e1280eb266322e1af44e8f309c633fb8f9472d9efbd1abeccf23d811bef72532be874178ddec4c3afcc56e0d5b8ff0932e569c586c34c421e3c9e24d6" },
                { "fi", "6cfbe8c602a8d37a0522806b6e7bd77e407ce4a77b3f595e6c1321e66dc693f42b1308f9e672bb9b72a80c6535bff5936eb304d346cbd5ef788d3a330aa3c693" },
                { "fr", "c858eaed39cb137e0fe5c10cb9bf6655efb17a1278a96afed40efe37e725f03f866773efd6ff27277b76b601afae63bc50021b49ca56d8de86cb292aa7e1d140" },
                { "fur", "d1e1d824d9dc8a46a05cece232b240db6a88d5a2596c02a1475e5e527ea7a875e07e83b9ecf2efb201f99f19e7b84430da20c2052cbb6e9048524fcf05b10944" },
                { "fy-NL", "ffd058936ed5bf43f27bb074db1b7a7095cf7c3b84855c807afce6781bb1ca30128f39ac35d30e366505f6e839e8a8612ddc4f2ad4e8598d350fb55125b5a699" },
                { "ga-IE", "910f2b40d66882eb211093b581d1f013ba20bdcacb7962943b2e9c7e8bbbf39af736462ab137ed9b0d47d75a2f7b62c8a73aed61404cb0ba4cf6905a0a789321" },
                { "gd", "d7de6f0a5891e9d795526089044756bd35adbbbcc099e9bf5707988716329d3895a8ef48682a34706d3f4e240b604541030b401bd7a3b8e160d0c9c889a2b9af" },
                { "gl", "41313bed26fcf1f94748646b0aeac7ca6059c86451bc0d9d2885f6166b0e11d01f927cc8ee42b0d6553a16055eed9b5f0ba2f39fa4df400114ed489ff61f20c9" },
                { "gn", "80c1b817b162628c8cbe3a2158559bfe95860177d88304d324302a5f78841083ef4d7ac69ea70bd0a9ee4ce5be13cea9503fc7f1d2faca0b0455acb89531041c" },
                { "gu-IN", "c002c317219019a27194b1b149a8028efeb2614cc6bcfd35cf19e9cafab23ee6507804589658d68094bb2de4e7967aad32dc7c312eb16524fe6881424c4c5898" },
                { "he", "9f1dc5553287f90ff7230d7d145f665875e60138081b3521186a1f78761b1afdce8d5975080e59e37479381914732f5a67d7b6aec1cb857a1f77b3b872b98c99" },
                { "hi-IN", "647a6cdde71ced432fadaeed754c3eba756d1b1b62670accfc89c3b911693e8963695f4fd540cd4a30547b464e8f0de20788f95d07c33b5886263e65d0dbf38e" },
                { "hr", "e5411dd34c933504c818127dbe86119f9b109164c9208466e1b8ddfd8f3072abf205d49525af9a3320d9aa76db077e33aa260a95d876f398e9e5c03f19a4a8b0" },
                { "hsb", "baf8b5e798a6782d66a6d261066accc0ab50313e45b47e6551e2e8f2c7fa71947791b9cf7df3c8e0b5d3b004ca9b0795cd0e059ee06bf59597a6e3e1624644b6" },
                { "hu", "02a169230c7de5ce92267ca04b023f89538c0ae738b5b03862404b9f9f02910e7015931f062ef2a354387a189d73fa047261d99d60cdcc5166f163a982fa7b29" },
                { "hy-AM", "8a834857e840aff485e51f62474fe4a74e0a06c415a566daaa0eb1c02376a4d953fb94ff36798928ae79704ce2e40da1254918a19e57983a3ef0eb2565965ad6" },
                { "ia", "493d62138076f194f9f19d504f09d96600f09abefb9db22764c933bc42351835d0e5545ddf005fd19ba0239d3a67fe7543a06cef4962c9d8bb1befd1d7ed7f9a" },
                { "id", "42dfeee8138d8455984e3158711789fc68b5fe22646246791b0b9827fe3c6ba3f0951a80cfcc4d61567d0430575c956c04833c7ec4702b3816b9843f822b5117" },
                { "is", "b112c6a57a7b24a0a881b32c71abc67f46557fff40ba92ba8547c8abf3fa0a8739b347b55b70ca808be6de4048ec9890401b371299371a5a735f82238875bd18" },
                { "it", "3bb496fa058f24677ae4e79e2aed73e94d30c1d3e879684dc1d188bba07d6443b2a72bb69e450eeca116a5b216f13de427311763d47bdfc850958fbeb199f3d9" },
                { "ja", "8222bf9399478a476a6c6c1bf90846f581ed9f1bf2a1799e06a7466cd448044d93f4756c02f721af8a9edebb7d2183e42fba917b6cff3b043a76923b37114717" },
                { "ka", "b76362d34a2f1b3265ddc93451cdf7fee654bc5a1f9b3f9ed0e00938ee4d719b8c92acec6daceb7cf65771d8f9a6f351b00bdcb1f5ded91cd3ee3c2924213c32" },
                { "kab", "4d386dfa115b68780fd23cc0fb79b1040a8eae5e0a5cfee1ee4b0de66c9447770ff52a5a6ea0882bdee0ea90103f0e185472c7bfaa08f99c962d59175c151ff5" },
                { "kk", "cc5111c92d62eaf775eea93d3b1b28fe4f442228d95a4eddf7a4bf35145782e6d2ffe4d179108db06276365bce04efb77b4b2d1d170db9e91a5564c9eb3a5373" },
                { "km", "7d4c981e0c8118347678d6ca1a973e047e7af4fe0a3b08317dd0afcc2de5caaf1c08bf0765b60d781a80ade360b26c3de540d991b2008060de11c22b1d71e5cd" },
                { "kn", "f657c7fdc321f671a62f76a433eff14d2e0f9c291428016c7d2e6fcdf83fe8a738b1d11eea7e602850776036af9eec386c11b60b0c70ebf950b3597e045480cb" },
                { "ko", "889aba975b996700764a3f4b148028216b026803c5355730c583642a79be918d419dd860ebee865b20e7e6729fa19549c2120b2759eda1b1f3cbcccf6b3822b6" },
                { "lij", "9813b71873334aef126b19f7ed836669f21251cd80e8907070789fd29b4e076a461bf587be1c91d58cb4e9a74ba1c902ee07206aecad0bb2344f7c835264563d" },
                { "lt", "5ba8348c2a9ee0fb22ed5ebe0e740ec0434dbacd651ad20c47030b4793680e6657e733976f970df3844741fc3cddf6e64d26efcc88a29f10368aecb342d08f62" },
                { "lv", "bdb62ebf421f17d2ee7a5bf06e34b6ec08fad46be36b2e57eba299d04f88dfaeb30a982ca3aa0ca1e693a6750cdd2b7563b6aadc6f43e5dbb73ebd4987b8b141" },
                { "mk", "ffca087e0935f1a2354f57e009f94aaadcaed9fe96a5e19c0d2aa97faceb548969a2aace932de84cc37ae2549c457967c5f59d77eb270e19cd7316b56ea1e993" },
                { "mr", "bac7d743178fcb467dcabb02f6b558a532deda94d996d26fdf410bd41dab575e888e11d2a6707ddf00509db1ded7e5d48445d302ffb53b4e70594cf8b2508951" },
                { "ms", "3356509a5a792f2f4c5c141d2f2ae165eeae71aae2ea2cb8e1d3a73bb792b0d2167e7999332da6ac8569bdea595fca3989032f66e3dccedac0d9b623ae1cb8d0" },
                { "my", "b71969bb59b781bff026561e5c424aa94e686e815ec95aca0c903ad251c8191fdbc4cb50995790bda17d523c61c3d062ba2ea52165fb1a8bce38aba41f5b9733" },
                { "nb-NO", "ec4ff81ced463e00639526b0971404ed8c535ab3f3cc61db81c0e908906f1de2bbae114025b2511f5d590bfc38b89a240c56e852acafb375502005d9a2978f4d" },
                { "ne-NP", "5efe6d6f2a8e63a729750af4c39e7a2d5ad7e50e2590f73a48247268cd408fea39ce1c6cb1b2d15756afa09250bbc2b43486f91c145b2c13a58285d3d23789ab" },
                { "nl", "987eff6acf839f243e7c7fcd0817102e0deceb15656d372785540d217952c4d27f1359993b5173844e82344bc951a636e907f1eebd34f56ca3c0730bebc066be" },
                { "nn-NO", "18192e52f9068e607d329eac7203836ecf45c75cc30f0718e58b93bb4d6d64bc82172d474f3d14631a259f332b64e85863386f32b47f441f6ff9af5b28e4d0b0" },
                { "oc", "eea580ec1a000c9eca7a696625eb412a22cf1ffc1a41a53431ef5a06c7521310f44adc7fe8c737311d24d04ce6d2ac0379f5212e185673c89051282bad61f586" },
                { "pa-IN", "e60ab5224edee2c1151f14c0ca83074962013b9a2ef44ce80f8111573c2f518fb7cfc6b88884b612ec3a33d06575c0227085eaf74a0ff36b8f2420eee496f616" },
                { "pl", "cb6c3c3f0cbf0255812f5f261656e24ddb5c85956816d0f5e9d79b690b0a1f53a515eeadd8b16d758154f6e057b5ba9f6e4f279b8c5a95c2c57fbce515f693a5" },
                { "pt-BR", "63086b4fdc9a8615d853652a57673ea49f4deb2a93d7e315739894d101de62a95378c455c87d5f20bdb52cc17f64c0d5e3f0f83a3d01aae03a5fe65bede829a1" },
                { "pt-PT", "6ab4e6c038f129e84d4473a1a72ef36b3adc3054d473d5ccc5d2b86d657f2a3e7d6b92ebd54053bb6edb23aaa0cb2c8e6d5d7b4e9f8ba3332ad6c22e8c5eb9a2" },
                { "rm", "bfc9afdee08443be86a899ccb52a0ccb772128b81a6655c4b0ad21809a75a7b9b05af2b12efb15de64183313ed7bd4b59832d4c764737d571ac99790f253a32d" },
                { "ro", "d3dbe0c13710fd78ae7cfcb7f4481bab33382ff2e4f846afee320e3be49800408c14e2810c2f0edd43878e87c15d9c9267b222a80ccbaa2f512631b285931bb5" },
                { "ru", "dc6bfa8918597ab80ba57dcd80fa7e8e330f5e9edf590591de08f1032747e2c5147138f3e3aec85622c7c4a9121e7eb6119fdd53dc8895de27551ab992143117" },
                { "sat", "ecef2327d92068a8cfb92d56143407dd57003002f154b5dd439abaaa3441902a8e0143f26dbe0f3dc316e62de0f526fa1dd80bae73cce7f0aa995048a146b3e8" },
                { "sc", "2e990e1621e33d8c98ba2160c73fb89fbed76dc384c5f99ce3ee6473aa55530dc702a50c904764507425a93bee7745fab22ea0d5205cc76359fc91689cc9e77a" },
                { "sco", "773fb774e59ba7c6c3452603b77b4ae9ecd2a8765b752658c3309df055a67f3fe74980a01482b92a0cb4db2eb1b84153b3c3ac76c6ad639c62ac56c9ae8f9075" },
                { "si", "48982a825851314069b4afec14f896695c73f71b611ec89446c28eb1604f00e827b1789a6e3884c7c20a648f07fe3089556180331ce36d12983b761759854ad2" },
                { "sk", "8d4d05e6469b6e085c2b7ab22fdb994862205e3b7e4549f662045a5fc70fad7dbb7ce7f814e502fae6c89f76b1698e2f56ac9ccae45b0418398bc84c5652b88b" },
                { "skr", "9eca788cc129f9731777d0e17dca7e459fa965b283405246c23c58cfb2e757d277ef41864a8afe0356dd368b7ed2820adb5f610279d24a8f97236c5303492fb1" },
                { "sl", "7a0ee157203def612f6634af4cd407c8aea76244711fdfd36ae4d2002bb2e338ee5e8388009e02dcf843c9b4e62db10ff1a447ebd118dc5e86aafbaeaa19e342" },
                { "son", "e4110093ce1cdf922863aef43865d8df1616f959ef2a8a62aa4c1387a341b77fd7da8dfb60b761bc43a2852d93683e42d81bf952c7fad8fc98c88a3bb2c0ddc8" },
                { "sq", "222e81c74bd4f2893edfb8fe71987dd69c1e5c559059de46fa85547b1b94da415fa504a191be1c3d1d9288d217f310ca2b05e39ce5e25e27318eeedf1478382d" },
                { "sr", "4c7993893b21e7ea56f3b35201eb95279aa3511096f2e633f69a65d16298497b714508a61bb6bc2265d8ce033047201164cabfb6d9bba5ba2668722c2c26fb13" },
                { "sv-SE", "59c722d0fe66786d48fc84769930f71a7137c0b31a29ce173a035a5989c5c0e6635c27eb2411bdb14c07dbeddf555ed3216d63f258e7aa9eedff623efdfcdb3c" },
                { "szl", "d5d23b4934e1c1f2c4ef8dd50dcbb58944652b679326c725e4c4d3fa7473528b6c1a57365a8b5754bcc5ce379d3cd1fc43f267646f902b24531ea961c2e7d99e" },
                { "ta", "defae736ada35bc18361aac2ddd86d3ecc421eef8a0f02d10c2a755049c0c42f86381e8cd1dc924291043d93730aaa5bad147eb11bd1e3fd536817a22e32e7f6" },
                { "te", "fd5253aab3f0bad6dc7d40287602f559d2699be8821aa94d065a1fe95a5dd970c0e9d66e97d63f6f25b04ae6dd465eed590338de9a78626b9ae2f8e46421742a" },
                { "tg", "69f3f773912d6891ad0fc262065e2d7142c6a89d9f4cd4a8a89f43d19e8ad84b83185afb407c0639df7a59d21d968507a8d8fee3f9ea8c560a2640af9672d805" },
                { "th", "5c30e2083bc7da84ccdf1db0ee9a5633815b230acc1619f6c01db6eb32e6be7c1be3a4f728b68c33ecb165904278c9a95f7439232496a30b4b1af52433b45cb0" },
                { "tl", "3108564a4dfcd67108c2b5bc34524c17f0c158227571b5b42cad20cff0a0d1c1a8b514ee6d9ed590f39783885638c566f4968bae59149ebf11a2fe1bbc7192a9" },
                { "tr", "95aed07008830a8720f5c855ddb73a55fff5380f398f57fe07116c84edde56f5ac816b41fb13cbbc9ca857cbd7777ca9b839c660cfe31484a1f3004cf1f41066" },
                { "trs", "f5f66edb055e0bc6142935f11418fd09779503d20748d7d8afba03793df15089c56f1753adf1779fa9220ab5abb3cbe9849319fac7f70b2b9478dcda1e9ca662" },
                { "uk", "350f3dbcefdabfb422618e15b3b75f85665eee08b5e7108477553d086ef35dd474dbc66b2085d173a16536d2bf76f98ea8c4113fa818cbd9fa9a4579e1d6cdb5" },
                { "ur", "41f53c967f1b2887be4e61ca5e2eee5c49e9a6a2fdfe70a39533e9de87dc95319ff4c2bb9b77ce0603ec333b666310eb7d646a08b1523fabfe164b8078a5b28c" },
                { "uz", "2d29d2568476e46cffc079e02ea3d728cb4db4a79d4ab300713ef03819404ccda538e32ee844a42faa764673e5b1ed0993308b1ea5b72d879617c34d5a4e906a" },
                { "vi", "a14315cb9d1d3670307633a65dbef8a7a187b4baa669afb0f8f3f4465955cdc567dcd02afee120540140bf3b4669dd9d7c639b1f31a70a7823bcbe438423f37a" },
                { "xh", "deb312d140216ebd145a4cad3b9767af69dd255a178d45a14fe05ab12081aca1eef943770bf399ecc5485f9717c5c38514408b2d64626ac0c8e56ccfd5543481" },
                { "zh-CN", "c953d999d4a455b7153cee98b1358e1e40b7442921f33c5c5b98613755647e4263f4c99fae72697923daea753aadf5ad632e230731376cea3721c66131740474" },
                { "zh-TW", "25fb82b43f44f1c5c3a20bda91889ef6294172171acf8bcd820123f76e9cbbd08e0ea3ef3dd28a0f8623ad6ec38c754dc2a60b8226caf84a87b5cc8be8dfb19d" }
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
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
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
                return versions[^1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
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
            return [.. sums];
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
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
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
        /// Determines whether the method searchForNewer() is implemented.
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
            return [];
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
