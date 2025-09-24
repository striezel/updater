/*
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
        private const string currentVersion = "144.0b5";


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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0d5ebae6fee25f9109767ecd1e70353bdf64ce828cdda50813fc5cd39d6874b228687ab1e9cdf53af143dcc7a5ca1d66a0278a99530d35c80bef77b20907e7f6" },
                { "af", "3a4b42039200ccf06c16b4804cc510ed2d1adbdf510a26ce620906abeaa05e9fe6099cedfd05659e3fce7d5794d322ce1aff7646a26ba9df28000ac0acdb525b" },
                { "an", "2b23869fe51b88ddd6b646d8d7c1371352b6f0192b7ca81db992133e1fad0da0a2fa71e55dabff703402f63b0550dd6be5a87159701c1c02f6d7d2717f066498" },
                { "ar", "45e8f39addf4c412ae59a0352a074e9c148f3f845bdc90ff2ab47ca7047b268b95e492194a40ef139c00962c4da23107a1e70990e132e0b4767809f5a247da1a" },
                { "ast", "cf99710a52827eb53b7fce29a7992a9ad04c8bbe9ab598e7c63d1088f6768398e86d3bb5a4852c341560e597d893bbab4e78e7509bd175fb4625c629f9b6db08" },
                { "az", "592330eb4f4f4d375c4ab7760055c0b30fc8a1bf08a54fd4bfdddc5670010a7a110d011df5f3922f15e487f3282bb8a026eec095eae4fbf9a6235dad787c2c15" },
                { "be", "a0e586420e157d2dc280e427d57610fd270954004700987abdf18c83d5b367d86f7049aaa1f40b52fe9183e885abd81081f8eecca0347143b274042f41b5db3d" },
                { "bg", "280f03f12bda229ad236e65d70b26858afff048348e1d2c5b007327aa439af601e3964688a856606c809eae7113c168940cf0fb09f67bfe8f5729e02fcae4b45" },
                { "bn", "eb131cc8fdd0ab582c9885bbdb5cae81cfb53f84acab2a4944f588fea50cbabe2ffcfaa6981b6b07e484f84f3568d46abe04768d368391b9ba0ddc643458b054" },
                { "br", "8974e434aed1a2c3f4dcd940d6126d4582d01b095a47e2161895430eaf5b29e176318d481eb53239674156228171d2ad37c1c0fe1cf8cb46acca44455a508f55" },
                { "bs", "7dd0adcffa75349b971186beab82ed81c615eda12584ffc8bbf25947f7447d36001fec87ba486f556d435a166d542149335ba43a04b9749a0324e6247ca7e384" },
                { "ca", "41341897abdafae38895f385843740202c87c1bb7c466c2fde77ebfa118bcb3bd8f1c5f4757906eb81bdf5ac46e66dfd2336629ef993476b86d0ece8d59fc8cf" },
                { "cak", "48fd5bbbc0f4548344e02116cfd58cf25c911672e23f6378aa05d3e70038cd604784ba94cf5ab09972b1b6b950af631f7a9c66531eb2f3a4e7db0c235954c04f" },
                { "cs", "156c04fd5660e690876109d984e3baf32e5a52aa0ab98854a1e97e75318aa4cf63e1c7a40f7dc58d12e7652ce29252175fee1e7bd320a5526527d0e9e1a29928" },
                { "cy", "57f2c4a19de888ed642d1a98f000fd0007252c593b5abdb744e65aa2900467a932b114dd9efd257ed6335bd78ae7ffeded3a8390a30d84920e82ea71a3c2ccd0" },
                { "da", "3ba2af8a89d9d136df022cfe2b24c3e942ac94241ca2cfe3f21d673ae89500ae16e89a918e3fb45b43e0c711366c345b8719cd8fb6b03293b515716829ce9695" },
                { "de", "d16a4a0c7920704b7a3060395372a71715ad7fbc5ec5a7f0a07b6de5723a26bb92c89677f5348173d3f8b80ee6bcb8e9d719c16e349388ebef0a8a78fca7669d" },
                { "dsb", "f12d7a9f8b0c003a3fa29c8c22710034e01576180770b12be7174c17a88761929831b83c6c5a7238ac3752ae2f972a7d420d947142eb7e639a43242a9ece10fb" },
                { "el", "33257fb012579c3dd306bcfb96bcd11d4101bf834f1b84ce2275cf4b7b5dd3c123cf27cbac4a4f9fd1b2328e667bd3414da781a42ee0fedb2f048ebfd5a2226d" },
                { "en-CA", "5d212ff7cb5ebb99d8f8a61f90a825df7af6861df344edfe40685fbbbb5e5fd4837d02d93b7f17b46147e6721c101fb9ca79e7c872df93861c7bbfdc9561d2bb" },
                { "en-GB", "f7172a114b836c9935e05e802af652ce6cfa65637a8454554f36e27697cc2dbdd34d65a3b70f93ab6de894fa463e88c6b748d60b6152a76505501a2d73de12e9" },
                { "en-US", "9c5160889735fcf80d3c2657aec5a9d20c8f7e6337ec394c54a100b522e9f7daa2118489ea9f777c5e21250646b7b4e1d005fdfc1f970f10ed5bec068438d855" },
                { "eo", "e79a90d2073bfa357f29d7200580803b1f1c7a2a8159191f38fae4257ab0415106b5551c0950f7c972736792dd14f8a490562e968de977667f436b3f937356c7" },
                { "es-AR", "f4a7013efc402d901988b5d20f180836967e4839e31661aaeb3be663b5f65e256dccc550dc88bd7942a26ea7108750eb4e921cdbd60686dcb873c0094a36fef7" },
                { "es-CL", "5d7206b8fc5866961750381ae1fabc2063f1f10f3e3eaef4226bc3cbaad6da705ed0a76916485494400b0909d57e2728218b5b4d73bfc4fbf611170883bf546a" },
                { "es-ES", "cb4e5c7f2a3fd0c45fa0d931fa061e165e0e2c362d3cf905c3712fa5eba04a64782f1dd304909576d72f32a3881e9f6f5ee6ffbf20bd0e470c6bf1f264e93e15" },
                { "es-MX", "38f96b2905320120eadab188c3cb36b2bb45e6357ae7d1a4cc34bba35c9869d4b935ab353556924d82ac6feabd18c6b6d01ccb5ae0307d8ba9309bdf26e1e7ba" },
                { "et", "0df625b9c4fd334ad07f3aa39f6709a0bb47f76903cf9d4e55031c6a79f8ad22e79e07fa7723e7c959b150bb6e00e0d9c87fe9ec9203bc0399c85503d2ce5f0a" },
                { "eu", "68da3c3c5cea1eaa332fa5b0bc83e22858e0afeaac0ef22cd48215941ebfd6e6c4a26a845e7a813b4c7684c01c6ce7f68ce7f32c1fb346f89ec090880b3d53f5" },
                { "fa", "f931dc01c0d4e993cd8cf687751c08ec842b28e1dafb2c64f55622baad4a36b2b86acbe1d23f9f79374e92dd0affd994006159a3bc6b364e2c30770d667b70ff" },
                { "ff", "c841315d81dfb53b1c4e82756f82c4fde8a14a9860449b04d15a7587b6b30ac112b5cab388210f578b4852300c0b78eb9a026a5ddaa57e4a59ed580a8d221854" },
                { "fi", "2d161d7feb4b853264c05c8411af2afb7f504090aff8e5f23920df737d52b2e852b6bb3d41cc8aec91ef8ea2d5b3f19bf47dfc58c3e7ea0206dd0fcb34f7b49b" },
                { "fr", "1a20f43f44cf502155a86b594b6a0086fbb2a966f0155aaed9e2c78388282113decb57c01a9df0bfe5a8e3b1f629ae04a77618309582184a0deb72398984fc56" },
                { "fur", "30bad66f87fddbc12bc0cdc7d8859b67fbadef70bbb2c89dac31918488d4f19c48587afb464f3f19f5c68fece9d40b1bcb6cb5f4bce0af98f2fb16c34bf73176" },
                { "fy-NL", "fc40ab97810ec4a81bc98384a581382ff90f82fcabb5f9455d3a7dfcba77338daef8f16bd1ef0a472e990b5e02b4169d024fdb68924a1db5e3bebaa843427e27" },
                { "ga-IE", "ce24755e7ef43547fb1d156c5031afd6ac9de508b761d49f136e7f1add3b7364843132d4b91c5211ce22dfcaa2bed8c9241fe8019be4be52455cc52b3d802476" },
                { "gd", "d99c4e18a1447919c97ea8f0ebced2fbb86472f70b91cbcf4914415de4fef63b55477824428371669414e0f33eddcedc4439c55859b5d1a47cad9b8233e0f527" },
                { "gl", "a623b601863c9397c7155f64a52b60ab087fa83a19e60502726eae8552d8ec6123ac2200fbdddc2eb04d5dc5fdc2534a3674db41fe39bfc9c9b8323817dd169d" },
                { "gn", "81d599646230a8c2230f84595a14f33a1f2e2997589e36df7e9b2907cccf48a39c98cad36a941884501fcb9d728d5d67205df59399bd328f07590b6a549b75d8" },
                { "gu-IN", "c4e6adc02b8ad1db9e163b6017926d93a36492cd57ecb9a37a9c24142d7f0b1f27423979bc00447d942badc2083a2068d73b2463074f8a05c2e856200a9b0bc2" },
                { "he", "cbf42cdc55b4295e4e2dc3f25d6efd8d3b9cd53217ce20e0a08fad313fa88383961f78a7ba67db9902871d5a910b853254c441d01120fa9a894b2d25d2d102fe" },
                { "hi-IN", "7e573430976b90bbfdc5e256ebc5e50857bdb46fde9fc924b63a487f801b9868e00e81df372d22de9a48255f304492a36fd38476c817d987ce9391df86bfcc16" },
                { "hr", "3718b3ed172d66df06c4db23b04d201bd175d2cf3a71fdcbc2e3ec82b887aabf37b20d6c2c5f5b5c72d0804eefdffcfd23796b856db3b6b1386864e447c1e0df" },
                { "hsb", "c94296bd399af1644a23aba14723bf2212c106e7daf32e0159584f9e3776ca96880849c78eacee4c2769d9ab1e3b69171e5e867c4b1c0be440e25692dd7050f1" },
                { "hu", "08d17197b13bbcf9f4bbcdc5d5de82cc10aa8032425c2aef6fd79fba336884a41e7fdb7a598f7ca59f7a134ac2a9b64358e15f54974715691f559cd2f8e186db" },
                { "hy-AM", "3808bfdee465f7f8506a9afa588cb84899f8d0ffee1acb3bdd087c8f2a143247e67a47d763ac9c6eb894cbc80f9a50d4d19c7d1c121c717c77e4d6748e22f58d" },
                { "ia", "856cdd9dcb32f34a67da7608aeca63197925bfbaf8ce359c1ff704c391fc0053b9edc53388943997140a57bc92165881d7c23e00b25e623d3e489ebecdef239a" },
                { "id", "9354d6da139e2c37c7589b7642f9df436e08b3b536f7e5ec4429f0b315a0c34b14892f42a23e0b46f99f849e16a445fe86fad5dd5aaa64eff120ccd2624777fc" },
                { "is", "a9f39a5a707530e1e060dab3eb68be68452c049ea943833f230d69c8a62d85cd6bc9d70088c3c2eff7d9939b15c9237244516105b469f931ea27d0b64a16c904" },
                { "it", "3c59b5ca01dbc2c6fe1d139f9be6a679565350a387888921df591e2dc5d636e1f99ba047fa5d49dc4e46403dbcd79a5b84d61f084d38ef8a8294a75b3c38c1ea" },
                { "ja", "d243e68418eaca152f9f0da7b6f1e6cf375f14ebdd0a1403f67141989d0f8b7f8d494f4de76003f6bbe1e1bbc35e1fc23d1933b9aec4431220d226d33e3d05fd" },
                { "ka", "06fb0a133b10bc3967385d614dc6f6d3efffd8a2481359f7674420332c4fdab3f971456c7301cf60962b3e590879a8522e8a71f433ac5d0ed82e0963fbb67697" },
                { "kab", "fa629ea63508d0003b5be944c7bed5a9bdb1c4e3281bffc3722cc3705843a32fc77b93cef2cb2d000729c411a248e3d1ce516aae1285d2d74474ab72fd6fa436" },
                { "kk", "ba55b0c5577cae531ba0335dded7df16b0410e457fb1efa232378ad25d65abd384bda6fa595d514b53408961e71bbdb3690d19af34774c384b0a6682317b7562" },
                { "km", "2a5307e6080c22b67aca0dddff205b28c4cc805c4f6152aac376623b11037034a5a951b903246b0b6a21cab361906a900f3a63797bff7e4dcb62495997cde1b8" },
                { "kn", "2de56acf1081bff0f258cabbd7d6b2c6f5b2b451ae9b7a4db423b15e579d45ee263af938021553c5b46ce4d48e8cf1ac44b455aa51bd3f7fc585cb7e92d1180a" },
                { "ko", "60a2ee589d05efa33872d6444d1ab1ecc1d77f696133e8097ffb5d67e400d2192222343e860e0fb36a8c382d8a022655ef4b95636e8ddaf4ddbba3aa2d57664f" },
                { "lij", "9a5cd6164d08cd18ca66c3941e97c32ccaf62f410cb167edbc7a2a9cbcbf2c3967df10718f1ab9ff1b61a8412e5bc0150f0e1580421403116a8c2cb8f6c3a6ee" },
                { "lt", "61fc3ca9f97a9e690cbf1521aef8fe1879d57c6b788a8994665a05e2564b8b18a4f7dd273acbb1fda2b54bc8160a83157182009b5a2b9f0ba8dc924cbf0ccee4" },
                { "lv", "eebb5f4ef805c38139980d625c62363111639649c0c2d5bcf6d18f3ac8342d938917df39676521382b0bc553609eba2bd6fdcb6a0aacf620ad55252ab2bef1d8" },
                { "mk", "7dc32eaff9e0207330272e61ffd90de357be686fd412cc2e1f178dbad767d43b7e14f5f03628ebcf855fb5224ed72a83fcc6a90d6ac02b5d817f6337002f4e8f" },
                { "mr", "06f8992774d71d975a3f177f4045a68f2e65b2afe63933e340cfa141836c47ebd9d3f733e9d96fec584695cf4c73af35f61e9c6a61f4edc573500fe249d2f156" },
                { "ms", "da52a0ae84ee4a73aac392c541e9228a8c7d928e0b35e93093a31f892ef1bc5738a874981008513364c4c6e7e6eb680db02b439dde3bd34a6ecb11ec01505107" },
                { "my", "d2126b10aea5f63566d3d97d7b0f19b128227246b0660c8f53c040d1e361d57452e1595ab6d8da035bd5caff043c1e50ae3d665eae3dceed7eca5abd0c898fd3" },
                { "nb-NO", "f81a8c14936506e8430124efc790fcc2d58bdd0809fb2de16e8f676e134a3c02e0bab39ed820421a4b524844f9bb7fb3ca4a01e041e07e56b5b8839a0a18d28e" },
                { "ne-NP", "eb12dba1600d673674a35c15e96402264ff802936d6e302432b2e974cde8e201d658b8278c1256e334b415dfaa2d00ff4ec4f6676aeac94b53968792432d3b29" },
                { "nl", "74548ee114fd287f7526cefaaf958dc9bdbb715fef59383eec72d7a6a41f4caaaf1d35affefdc2e3b48ac6582ae509883c1c6828bddc55575c54bb98583ca054" },
                { "nn-NO", "8d685cd33436cb8b01ea4a876756bcfb68655a943853df865c8b1ac3e9db37d126220eb3dde67388a9a16f1504dd7d4f159cb7f969367da2fc23920b028ba9d8" },
                { "oc", "b518dc7e22390e752edb0b9a1b065eabd53b6bd87fea31fdede89b729be4e1e964d7d64b1018028497f19ccd33c032d9c7fd98d6f81097eb6ca6e289cf0d879e" },
                { "pa-IN", "42228167e8679d83e4be561bca0a0a80c6efb0fddd5e134a8052e25701e46a4ad89014d0a2bea8785e70666848ae0bd0cae4ac7a8409dcba50e606998863773c" },
                { "pl", "266045bf5dbe2e7cd4c9944ea10e13711c1aac79c73ef19cf1ccaf5fec2347eb4229084fc2f7e0c317bc0ccbc607d3fe5016cf3870d8eb22c84199981a798122" },
                { "pt-BR", "c185f61332f31b8bb0817ca43f191f8bc1c6a328524192fece75d07501287157673ea900045b037ccdc1e3c532e87daaa44042c18e92f9a9e69c0203cb0e5db2" },
                { "pt-PT", "09c6b6fb8a08a92f79f419b7828ac000b5607848363b0f8fd8a1744ce69024d8a02e07f35b341557ef394ac167372358edb69b1a40801e7d2d4d565c58a516c2" },
                { "rm", "4d99217ace56133b7aedad3b3678ce08d2811ecaf4a00794445ef9b61b7dd7012d54715ba1c35b95f7671c69394681bd8462ece3ba6e2b99d884dd7c1625b971" },
                { "ro", "9dbc2bc71d9df8513f7b1b9572c0ec29b37ef4a12ebc56b7c48272d16c3b42d0a1ab23f9de56a8c606095c514a192d304d061fe7bc127313820b3ab2799d02e0" },
                { "ru", "bf8aeb370162289b07cf396532ab0226153b6b3fe9104f16f1436767b279369394cb153b8a8ece4e26db3a26494d0936fd06babb8bb573a821ff788d8e124b54" },
                { "sat", "d733a8558a5104ccb96d4343d828eab65603ee9e802e6161becf152224ef9834e1adf24ae6519228e526c85360a9e817b11e48b22d195fbf6aa914f75e4f8395" },
                { "sc", "149cbdba6ee7041899b38067e098221b17801b53575d18f3f99aec3ef18a5be746fadfa8d1d031a99d0f4298193ade50999dfcedb70c5d3342b3f3f44b74977c" },
                { "sco", "29f6c721191239dc3d8b268cce72f2638c1fae1076d323d6001c13a5a5a30dbf8c25df07e8b8cfbb58e95e08076f3de5feaab31cac4da7598109cc76b19bcd28" },
                { "si", "ee0b3b1ace32545c00850e60f006e125a825d735447b9c3b7bacdb9639b89f705bbb612dae2e98109a0a11d3499f18402fddc511ea73c8c94ff361f3631dc653" },
                { "sk", "806ef0f7c153c04b4565d3870b6cae9e846c99d48e642517cd3b785ef44f37ff6ae96f7e926792f260c10c92412dbe9ee187901e0d9ed718ea62301f27907dd2" },
                { "skr", "9d278e283b1375909d61964a15a1271d705a265c108d8731362759bd04d4a6e8bb91364341831827ad741b0a5e49556fc12a6d4157997755046ffb9fa6b6278f" },
                { "sl", "659c644f7febd39dd1bdccc601ab977a882b29221540c5eb12f59f021f89e0aab495ac625a1521e3fe58b96289c9f562deb8a18aa3148164bc0f41c4ae4fb5b1" },
                { "son", "019f432495fae0fb723a33c9ab2bbcb5afd68e2fb66b1d57fa15fc3830ba34e1b0d5dea34d54f6e10377f6bb2c075ff93f79276b9a851edd62bd64c518e4e00c" },
                { "sq", "7530a20f31a8715d78860df890225838ab3042b43615adfc6714af36aface0b4eba38e2f2893ec6ab6613210e645510562178820703dc7963e329d218c47ac96" },
                { "sr", "f6bc9f4a78df0e8e4c8eb67b4b295d9874c448757f75fba92ad159f5d1dddbb7c82c50866e3b35f99109c4825750a6b30a5a711150af8f5abdedc22c0ba4c4f8" },
                { "sv-SE", "6f4ab880ca62c2b6aada5f7ad213767a6d7f28a2e48c6d2a92d3139d08806368f4e67b188d9efa0d64da8538b24700fe12b8124f296554d053371a9c68859951" },
                { "szl", "a94df5ea226801895f58f1043d32ac09c911f6555fa32245d3227c5d94cbfb5e1792a6531a26dbc80603bbf9dbccdb4053b28aff1336f4dd9ed6b90024f50e36" },
                { "ta", "c37cbfded014e4ba6b965416d043a23757262b5e856a2355838831b13b28b0616059cb6930885a778334a5f1a1b8b66861b04038fbd6c44b8cfab61fbfab3358" },
                { "te", "c2939eb3b5c707b8e338bb350e7603d2df761834c558a3729322f18dd75288d9794eeac19744849ca1820f81fe3c59409933401e9b0bd10f274bde578ac47c2d" },
                { "tg", "017958949dc9b6d5bac74c56f5c4689221d45407988d56681ba533b389240f9ab6fbfe488b976c186eabd5f1bee12661b7bfa35855e6db2aab27c1a20712930c" },
                { "th", "286b053135326433ea4817532d72dbcb09c1ca10cb7b36a9a964c2b36c4c49232df4afe581da357cbd9ba396bb5f4c3a33084b8fa85b73621f5e1bed1e5d9349" },
                { "tl", "b6d123e3295718629db3ece76134f05658f7e9eaea52f1db4a96cab5e6e4d0cbdaa937637c58e2039b7786abdb63a44fe0d8b33e558ae30dd264421ed5f83cf6" },
                { "tr", "d4676a5c7e021a70f05575da9c1f5919d69bcfb1fd6c3e19ca87aa8f8ffc9797a30ce78821e17df709fd829327ecbb3ca3f1c88db1ad44d699bd41e8c51093ea" },
                { "trs", "b6e48e578e67f4e74a1f5b663f1ca9b5fce6a851c46382ea6b59b7f691bc8340ea4b75228523ba3c761d7b7d8ea28ec5c2a3393f50102bef05af3654fcac783a" },
                { "uk", "2008329c3ddb4a45bb0545ee634f3b70b0e6469393f06e8fbfa729b6f339ac7050363e55718955e1edba37e2804f7df16d7b28374ed6e02d40f11928c2cdbbf3" },
                { "ur", "defa5c5d53bc1debba7421a2d33978522b5ee7206c4fa39af74bf5e756012d31027f4e76d8ad62b0dd56abe024c5765752ae2fafee33028e685fb920922436dc" },
                { "uz", "95edf0a1e6b38fedde070b27817f32f79f095f81b092800ef7df6edd6ed18cb5887232a68315bf0529b52256d3639aae2e46ed9edb75cd70a86ca5ac10937305" },
                { "vi", "9105a417a6042970d7068566170f212490fe6122ddb5df8d78b995007388b1267c8261d0a8a26abcb097c14b5e2ddbaa1531a82810b50f761239e214fe09eeff" },
                { "xh", "e2c6aa12809ebc1c628ff3f4cb279f0953649a2a51371316d8ae8e96438f08479196cd1383aeed0c82933112e83f9029180f6dbe1012adf1fa2216c07ab0cb36" },
                { "zh-CN", "a9e636bde593092b51f37804704f5c88dab947deeae573d71b81932d651417b465541258e2af8f497f1b5bcbb5224a288c2381dc6686192427ffb35f984ce925" },
                { "zh-TW", "5f229022d538f3df48d39862c83f938177bdc68744cadea2312ad886fe786623b8385d1f68fcc4e0c17ca3a63c2fa8c0d9a14ad8f6bff2e8bd72b515a92da560" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8663af39336601f23c5aedd76b284da234faa8e5edeaf11bb9e6f7fed05038f92ab6a933d2e8c6313643cb1d48233f731e13c958adf9ea4d6aebba6ff8ad126d" },
                { "af", "8bb96f67a1475ce3c1891d3a2f964b689901ef3bb09336f80ccd1851ab431f169d044418646df243ebd2997e94eec52360f1793035fdccbbfdb63f99e89402e3" },
                { "an", "1f2e62c35e5dfab64d0b3a26187268fbc48097402fb58910ff0aaf235eee1ca57a2496f502f451955e85fa9d944e734b7e86326ead9a231f4d17e01c1858bdd9" },
                { "ar", "e63f4457bc07cadb623925b48a4af38113176d2d9b452796ca6ed172eedfe50e47e2525d51ac188c2b1618ce24a19d404ef16b01c677b0ff0a85849bf951408e" },
                { "ast", "06a3b5e96c0124f845f09a0b5c56e987102ffe81b2a8f19b711638402ce75428248da3dc83f5244aee6414f7cb5857fa36a1b3ad18df1ee34fbbfd59e18ed3c6" },
                { "az", "09404a0424be88b143e21a19d233374d6293beb277687c14b1a1ccab3803968f0442f7c7058812c4b12063ed8078656b9ff5a7b9a1de9c4d9cd09ef5fcb9a1b3" },
                { "be", "b194081e3a64c143959f659898964cf531a30d0730a63b5ee879c7fb2ba1347f9e540bc65c138044eed413df747c1427acc7cf98bcc69a2fbc589b05fe2d690b" },
                { "bg", "9de0d022847aefd812c2b2ef3f58d757e56a1478dd64bd219ca9ad59973775152b17309b43feb7ac606f2b29e0e8fc3c8361cd4762d0beef6fdad09a2f444cb9" },
                { "bn", "e48fc27278d80055463082bafc3b2ca5e38a7976066585e4bdfc37f13c3391473ce6ca09362e8d09e4fa4e850708771d83bbb7336a72b61d55e6b8f4d4e4a1be" },
                { "br", "25c2247af27af9ecf4163c1f2d2c19fb605dada1490cedc0403ac8feee1cff0b5d5ed89786412cee63f092e5886065e6dd7d7d58706f44501d2450ccec7734bc" },
                { "bs", "e60dd7a37111ced47375fbe5ec50d3753650d40d8829313882b433d92937454b60959415d222561140f4e817877c6faa2103fc1be8627cf43a0ea46ac8867167" },
                { "ca", "2acb73bdf15366b42073be6fa74b0d0a1bad255b686945ebadef3fd2efe9657e644b14ce3ed91db7bbd0bc4bbe1db3e1b6b666afff438ff395241a96c461c090" },
                { "cak", "90be432f4056a5a5e793387fc81679f461aa1a7d63ed546b1adfaa558c6412b12676ba029315b9b3394836f0865c3a77af9fccd151e4500476bd59de86b5347c" },
                { "cs", "c66c89f001051ed216b852098fc7f149aea2470e003e9846d6bec0aa0e9569ecf16e92b7317ac2000ed75cd0722071c2d3fe74bcef82ac9178301613ee4aff77" },
                { "cy", "b9ee86ab5d7a8eecf1c24b7f47716ad652e3309671e0c60f02700fc248a48c692126e1d2a82ee472e663a7a10d76518153faefc874b869dc9897c10803b546ca" },
                { "da", "af23b978c7c2046394863709a564526e4fc01b04bd32ad5e5d60939ea5753d90fe5142221372e07c54d08fe485f7b52911ed89216e67fa408c1309d6a6e439df" },
                { "de", "0e3504957b83f3820caa85bbd49ff1bb58ccf9b83d6d562be757177a4f48c788558d510593945ca27507dec6526882e1c08507bab47707d3d42960cf2a57fb1f" },
                { "dsb", "7610ab44e4c3bb2f884ad57bb6d56b0b2322998c74e39f255616e697a0d0858f8e05551198c3418be33c015a9825170a90467f6946610e0fc49510e150e418f0" },
                { "el", "d1b41f9d83db593d9aca9af947a9e6d42f35ecb6903446f18e6fb2ad4070621de88d28407f4205843f38b9c8ead6c8f302ed040cfab062b9ddd546403d6baa4d" },
                { "en-CA", "725b8c10dd75d251a1ff56eb612a90d67d1c0285d74b7789365bd500d3808ae57a583b56c9441433b13acc0de5cd3a7c47a53d7e206d29ca89fc6f8ba6bb7c8d" },
                { "en-GB", "271c78b44a4fdadca373f98e899615dfc49817d1b86bdae8c235eaea63ac5fa4c194500c0e244a5a4cbc21c5b84c91fb3c6f36c388a0647b3265ac3669e1fdb7" },
                { "en-US", "24d2668ec6bb567d7918562357ebac13aa060024f312ca69d90a6fd312a1db67755db376b4c8d763693b3d8ff1077295e7cba4a06b1c218f47766a62eab3cc0f" },
                { "eo", "305f2514b134eab00acd5e65a17970c87e27097288cc8ffc7cf8a4a4a25ffa487374ad5080ed0364780da094d3b1937e68bfa843a5fc9488a05540155bb8de65" },
                { "es-AR", "e5b36608695505e21650f4beb42d21552e5ead2564e71b7b28a9f673bc6a277e0e772768f9d042182abc7b0f2cd49ffea79cdb82bcc223be1f82b7d9f600483a" },
                { "es-CL", "316c9c55e2d492c3d9a0bafa118d9898232095fb33dd7c3b70a5b26a99b33d82e8e837a0fd88629dd6f7c8a487413a3e42e70860b9f9a1460c034e72b3d59330" },
                { "es-ES", "225e7a85c4e6e6bdbd2a041fc4a7e682ab35973f939690484433eaa065d03e2c40f20e2d41c11abd38d905ba23dab2270188019c5eb82d6e132c164fc1a1aaeb" },
                { "es-MX", "4926c913807d06382dfe7b3227db63f6c8d202932ba898714ff6fa8a6398d9d03185f25b566cf5549934b38c53c3f0090886f3ad7ae26420b3b254ccead49785" },
                { "et", "886d916341959681448b0c5fdd1dbeb53f7712177af484575c5d7b00472208d4340468391992146a066614a94392747e64800e7ad426215a02b42fdb99a7e2ba" },
                { "eu", "79e53105ac758a3450cb3246c16f2fd438dab5b2e90d2f04e0cdb54e6a058df700235c89de1370191510f4c0683c9bf5c7086575b46ed64164ae4d5a095ef346" },
                { "fa", "435c98c9b1885e185f87f477174d42ab8f6df3e17d4773525d147ffda7bafc779b29caf2752cd42e4b4be4215e353229dde8cd5ad8c0ad1de72eeafb57f0ea65" },
                { "ff", "0175ad21404dddb44673cad065e554bc3d57c661d4410ccfc94a517358e51e2cfb7177fb990554ac43eb988b85bc1743ae00d3e3de1aa140c0a6c18c86576969" },
                { "fi", "98c7b25f5dd55762126ad0dfeac17d0857e5969204ed86a4817d3af93df13ba80f9221493e3b94c2258398f30db3da1a363f1033b9c100d08eedcae9a2462b2e" },
                { "fr", "66a571de8bfc9937023023e7f0132de265cc2ac7c4d022d8580a0198cacad065c51f487dc72437c14f4f40540703ee37b4e50c380c09f19967ef393763a7df44" },
                { "fur", "24b303e514e3f83f99abeb6d56e0faec9777285127c3068c990e1c09524ee1ef36db2e63584a55f48d3e996b00c94bf4d6036cd31dee7cdfc4313199982c7da0" },
                { "fy-NL", "d13af6486e1ba06468594c0c2988b0ebffa4f234008c6f178c4dca43a17ed53a51bee34ef3fea81174669809c7c991785c87074a9e46d7d65afe2f81b9bfb774" },
                { "ga-IE", "ed0877b854b169703ae37bc56364b2f42fd47931e75e9990e38061d1a08ab476b2f9832227225cdad2490877f176bd9b0aa8d11489db5c3bf0364a010097bba0" },
                { "gd", "df902f6f8c96ac531499f37f1e0019c8d9ca7b9d004031f14077876446fd6e7e9a0805751e26247e6ed563da823212694507f7e4519022cbc127b3901064b56f" },
                { "gl", "444b66682ec8c8b800a85d3a0a9ef3479987125f43292ff657652b52c2ceec32acff44e25256250ae28cf55cea25a49fe6a261d2466c0f51693bec11a7351a19" },
                { "gn", "76cbd157aeb6bc4a83ec8baf4f2e552f97bf2ab31b240b7f1a990ad60e2f8819b1108f18e3b2279b8657d4d80c81a32460b846449d46afa1dfbe379799982a63" },
                { "gu-IN", "50ec6daaa32a273e1256214c3fdf4c8f658cad04e0e16275a0850e06670db8fbfb40dcab9bb640efa975910cd68807dc0ac36d08c51b7ee8eb94e3ccfd34efbd" },
                { "he", "5fd0fbddbcb5fed535c7641ea58a88ad45e413df2202e0ca3d777b41fe96c43eba5043a4e69f5851b56db541d9302ccaaacab785d2a095e2c282d13c34b2a6a5" },
                { "hi-IN", "f08dd6d9a5aa449e98472f291cdfaf2373491a8f2bd0c6044c44fd23d684dfdec1bcf1bf69c87bb62380474767995b7e6665a4208f3a0a9267eb5a9265eab80f" },
                { "hr", "82c72697397f28af7bad571a04d9a99ef2ba367ff7e469fc2dd82ca17dede2e59e0ee722c0455d85daeadb62aec79006f2f9cbafe2299d01d395c8ba3ad3beea" },
                { "hsb", "ea9e014876e6cb0992353a8019752dbcecebf06929a022e9919d2fee738776af02fc7aa1f925a4e594d3baacdac68f7a9a57def1ec2a6d4d77235bb040f551d4" },
                { "hu", "33cf1256d098f5a85d967bd6a7baf9c68bbb958087c68ef3c6fae051b34e3a4fcacbd4ac1ab5b5693366c07b7096cdfdc764a1acdb4bc69a227921633bd526d7" },
                { "hy-AM", "57710a4fd53e39f2e0c20cb2fa090745d5ac891b32d96e2bdba00de9539796bf37d127bd40937bec94434bebfb42bd3487bac7a91e4bbd0a31a8f7ac0f5f14e5" },
                { "ia", "23295b49860087a75ef758f4d320a3f1b381cd27c9accc294efb58b0ab2e34dcf2ff0c5ef8afe4598f78017860840f10ed83b63d2b6d2915cea00b7844cccafb" },
                { "id", "67fbf4a8a2703692b6272b04326043f46fe584ce70de0f252856bf8ffd3d96e7dba837759ec902f78a8fb3c6ba58b873499b0c081433643673258f78e59892a8" },
                { "is", "d06e4840f3a39a6842a856ecb1dace4c7c4af36128a39477fd0ad39c076593999f7a864451848214b0f6650f846af998dee3c2d0bf6ba8de26919bdfe0af9d7f" },
                { "it", "31ef34761f6c29ca7e63b115f1e13cd8628313f4c589c274bb43989adbf486974b41ce0a0ea04c53becea2bb4a610d56d34c34cc991d5430bcbea6eaed6df670" },
                { "ja", "33821fc39e8831e08f5e72ca5ba59a90063631fdba6bc46eb892317bb9da4bdc2df5da73c1cd55b47d6afc1b37a77656917d3324017ba7556993d0a91ea1a6f5" },
                { "ka", "cdb658e64a9ab87c0bbeb126aa0a241fa112d688289296ff14026336e581c54829111db24bd71c2730e1670931055e058dd9baadff881299c93bf0241738feb1" },
                { "kab", "5d6a7ffada9470339225181cfe9ca6b388536b4beb393edae068c340f8e54a0221388e2d4b13cfd8e6cd5d0f84b636fedcfdffbc8217d69dcbe1fefdb058239d" },
                { "kk", "9eb5cb460c179bb7069e157d3e531ad9c9beb8433d4a29675c3722497236230811cf6caae48258ef2112958a66cdd0e7ee7208e52fb106c974fd1733ec702a02" },
                { "km", "71bd65738c31e8abac5ad68cba6323acf188ab7a458047460eff3e41217e7eefebafe52ec07941a486be7bbdbf3e4c0c09b094733ee38c6764083bb183061ad8" },
                { "kn", "480be3ce73070893b20f416da6d55bcf786ccba0d52c89b0e0eab565d2b16f32ab52f79454bd084d3269285af6c9d866125b17181f60d6943e865286aac8f203" },
                { "ko", "876f62e0427090a2392972995a5b74fe1329fdfb70001edf17814629705668cf352ec854644ca26f105f540832ab17ae7951c9b612a982c95b262a6424cef895" },
                { "lij", "4e7a43596b2a71a197270ffe4f5c66692f72daed3deebfd2f381c7bdcbfdf38129e6fa2db03cbcc1a5b78da0338d21dfafa683f66228575019250b32ea6f1fd1" },
                { "lt", "d0d16469595560c41c41cb3c9e8518c55bef5636a507d5b103c7a06aec6f98e12634babe76c086db19c2756ed459ad8615bcd8acee97b2cf6cf56c3df69a9eeb" },
                { "lv", "013fd706c4297e545547e383939f9561b260854ae1d68be7fd3b0bda56cd905c727a34b25db150c5584423077422a69b0c425636df4825642f5e10c71a728cb1" },
                { "mk", "d46ad581d5be9793352a5e031d919e2274ed1e6ba1a044a1267a84c3c803afda93af1c8f0b1b2d3e975dbce14f30fd947c5249ff293ddfb3683074ac9c50eb59" },
                { "mr", "4cd8822887254d035488b0bfced0ec3e2833ce8bee6355780b378178f0542660d1ecb3fda71906e5d5d3490416e585ac41328164d69a33c0af0c9fcca1c313a8" },
                { "ms", "93664d33809fddafe05397d9b84ff6ee836a832876a62c925ecc3a43ce6e352316189ae1e508a1d8254724053a428a45bb8239f0fbd5192b912f8d64d46f3ce5" },
                { "my", "79bb5d87c808b2ce7e660408e3d06d8e6d4ce3c87de65f8ac553a0530e23ccf1c8aff0ab869033ed93ae72e55a494865f4edd4e6603272ad261147393a11120c" },
                { "nb-NO", "562b967497ad939703488e0f2963d5a9d730fa6c5d52a246b3aa04626cc140b849c964468bd731d28f48377997a734de7da3f83abc73f7f4c90139c0118794a0" },
                { "ne-NP", "0c38578410ad29ef8feedee479f4e7a894b72367c2cf37b5acc8e3ea1dffdaf812c48dff576de1d3b0e34d83b543eab6bef26a8d8a748e840692fab12ebfb3e5" },
                { "nl", "ed7de8a597d434297248afd2c5102c717629cb87569d0d9f3351ffb0ad0fe307f4ebcf7b0ef44255acc576841a45cada5be4ce5643416d2be47d235fcc8b0a3c" },
                { "nn-NO", "90b64320a07fee39c6b7d96bfe074b15fc9ccfd35f04bca9e7b5f4544b5fea17d14b1c3f8501e9f771662461ed97f1fec6caacf782a90fb661b8d084def1e234" },
                { "oc", "8368759b3f9b91262c1aae8dee7a819aa838ec197557ad647e5bafa84bac24d80a0f218982a5f98b5e6e7ac6025077a080b54fd0bf38dc9770a0a6e83f716bd1" },
                { "pa-IN", "06c77c7e126bbfd8e9ece84654d4466b1ad53e975575e9b333d95bcc2f541c156b1ce83bfd77236e216a69999f7cefc3b54dd3b6957cb6ebd5da3a8d9ccd77aa" },
                { "pl", "1ba6113e2c70cfea0cb65333054f735749f7831a5fd9ef305bcf97a27804f4fc542ac25610e5fa883256a2b5c2bbf4dc31d099a65645042b3fe4678fdfc16ffe" },
                { "pt-BR", "e94f15aa31d00833d43def6d8fe06aa4e32576e29af8ebdab9d2b72ae3887549b23a081819890b8e9cce7f48d8d8f41e4c5851dc739271eda46acb614a61cf26" },
                { "pt-PT", "f118d59571d891934c4de1396831a18262362e3d2fa7ae3852828a2b177444d9fb6c8421a313a90be0c215be50e55f19282e8905b127a73e82d1cb96e5bd780f" },
                { "rm", "17a1fdcd441ba578a64c0af02ee0e34cd2200180aa15d12507c2a09e4f750cc739dec518dc4e1a6223fc1d0eaf860560361fa17ae8e2285ce39fc9a3dbeaa676" },
                { "ro", "862572a14324968fd6d1983b564f7321793c8e4cdff8366ec44594ce6ebae25298e66328fe39e11c40d1b10148239360dd24c815bdcfc9ed8bfe20a335ea5549" },
                { "ru", "c49c6d0bba278def9e557a2e4125521d517d47768867a3bd010ecf79ec6e3a4fb397c719338da083d550a4b399c3d2d0960690f4d11d7e7afa538e190aa73244" },
                { "sat", "919285c9275d993e6f00a74bbca4f60a36ecfdd91dd836a60fb9f0439355cc0316582b5e0b8d32540ab702d6a1010953ff6b3e87592a692c9210cf8d9cd37cdb" },
                { "sc", "513b5205c5f4d5ba65174ed37d072aee8ee8b4f3a541bec8a3da91ca0defd0872a2b8d90d283a261c75bf4ddfa38b6b2147e2f5d6d3ddde57c4321fc0066627b" },
                { "sco", "20f7b4d1939d0a641f8dc7463ebd05ac3cd3478abedefe11819e01f5b01b528132911e95feab48661990c8a809ea7eed4be0640b37e28c003c776823f6e7efb8" },
                { "si", "2921f8da95ad6236bc77386cf111eb7069aeff6c507f5da23b5e56987742589bbc56a865e58bffb9f73c199776a5df6cc650c5356ea4362b53e3fc7585745060" },
                { "sk", "4407191da2f181a08d38f291c99f5b6f05b914dc07f1c499208748718a28c19e213b0b29ffe79880925e3c1a6a35205f11fdce7a84452fdb256dd1e1beb451f3" },
                { "skr", "5837e1346bc48a0e521407dfc15a800cee89718fc6b7d46048df18e4064490c6d5f117b3210ea259d26809833882616b6d00fa685a79c1f4e584bb6c30e57b3a" },
                { "sl", "856814195856ef92bcc77439afbfae7d2ecb510ce806b6374d256ef36317f7bcd47a1a5b2921a1bc16f57448a12aa5bb6e5e9139b7cc6b7395c446b7780b83a7" },
                { "son", "d18dbd0277782613d3687823418ebe4aea822d2b5c1ab384384e481b974589e939a412155c4821752982fefab2a6de5e0fc5061c10b5ad8768d45dabb1ff9cd5" },
                { "sq", "24f863805a7f8352e5389b9bc5b953aa05f6ec8923543bdd34160783781f9f2315c094da5e35b2bd51083985d9b7d71312fa8cc139f185be01853604102dcc84" },
                { "sr", "ff22e8b2a656a61ac9e4820c75358d41b29ae33937921108230d516f25ea6f610577ca0934fbe149a7acbbf68f754c512bae91d342f47309d0f33d60ef0186f7" },
                { "sv-SE", "16c1ef86ec6e5002640d68083399aade7ac09f760d12fa554a0adf107165f140b3bd55e993c640b7d9554df04eabd8d32f839b385c381279025bfae21cc25189" },
                { "szl", "451421af931077fd1eda327ed42f6b64417b8cfb7e97b403c101dc8416bd5fec4b3371a8e2670943c1f7b52aa6bcd21ebdee2ef05166a484fd282160ded0f594" },
                { "ta", "bc58662150340d2f79bcffeae53fa9a3270dab03849f674ebb4e4148cabeb836346ad515ea07696ca24b5bd1a0d00e43e776389e93c69404515037b36f3a3de0" },
                { "te", "a307060a2b8e1bb8852fa550a500227dfb1c86e9e04d317d8b7aea013472a8cffe5f388ab2db979fbb9120812ccd8b5429bb63e7508664bff3e6dbd872664dd5" },
                { "tg", "702544b47a48c3ca6f68c883ce501ecc264d56bcadfb02a4c72bf9f7d86608c9db45ee27bcb75e2920eec9a9f6869641303e3cc9dcbf505e4bffaa99247c1b4c" },
                { "th", "2ef32d49fe6c9549a80e2260a79e84a6d36ca1d975b4bf2768c8ec53ac1cb8f1665970838395ce6f0af23014122290d4933b2aad2c8bac6f9e976bb451416ca5" },
                { "tl", "69e78d1370cadbf48f57fd6a856899c01ba875ca3ad47bb076c6ec410330136c656d522df538afbcf18d232ebe59fcf1820c6dcd36b8443a6bef77e7a4f33ae6" },
                { "tr", "83725e993bbb12b822de0ef6fa1f1d15751c4ff146ae218cfb7cf3b7ef11aab7cb1becf314b2a08ea3d0cb7825264dd3f6746cd08a521bf183b7be348681feef" },
                { "trs", "5ca58b9e477ff0ab60066347cc1ffd51973837f4091a43539caf1e177b1f2d851c56aecf1b12ec2ce57fb462b76931d54281f16da44fdaa6e6de1807c37962de" },
                { "uk", "7a8fbcd8836b7f3119e75cff315e19375fa31b1192d64b38c55c05c00b56820ab7cdf8c04f060ec4ccbed6beb3328ab1092f7c9c6e6adfca81c55e41be0b00e0" },
                { "ur", "8484523b167af1cf5d349c7fdd935bf251d3310337c1b5e391766e257c21653b6d5f98e4e49163d2c75a56fa9d1896b35432f84cb8bab0a0a2a3b14e91113878" },
                { "uz", "d2dd641c39570356896041c6ab6bb413aa0a31bad6a66a3724c225a19b884f686c7f44446321b45b1fcca0fdbc981a071ae9e1a109b4a903c60d49b027790b7b" },
                { "vi", "6dffd0db14f4867462cbd7dae43d7fccf1625ece26a1e19e88eb583890de5bf6625e132f27587a3644843bfa047da415eef520ee30cc105544d72ba85f5a017e" },
                { "xh", "ee7fc3d1c69c16cb5ce647d7f363c33fe65ae1dca740e10feabef6377d94ff3341e6ba67efb0ad963ed6cb71e87df24b5f1569ee77115540825a77b6e639c481" },
                { "zh-CN", "0b1e5bd7c4df605d4893d22d5016f6131d3412ab86fb0bae9c682674948a3ed0d5c2207723fec63d38af7b33733c77ec35ddfdda3ffe1dc6617844bd7f31197a" },
                { "zh-TW", "e733a2c445471ca3b0ba0019e3230a6a02d0bf836271ff58b74debe6acc89c0c6cf3211bd3d5731d5dd197e293fd4aeb7b99f6d8a6254bef1d8196e3701bce0d" }
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
