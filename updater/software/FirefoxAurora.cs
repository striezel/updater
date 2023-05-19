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
        private const string currentVersion = "114.0b6";

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
            // https://ftp.mozilla.org/pub/devedition/releases/114.0b6/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "ff1e756804c2b499655c243ca2c6a9237ed1673c6e80fadeac3c2a805474bbcb10c871073b069bf55f75075d830d5c35a6d14a3bd2e0122351ad1ded9e70a168" },
                { "af", "75690e12d472d0125e87d7e13d0a9e38a003e43fa883465842c0b1bda87bede6c58efc84cc06de3e30677ec1f8c9aa3b246fdea7e35a52b559ee4bffa9b52cdf" },
                { "an", "c9ed0dd15cacda7d5fbef6c303ffbd91f5607091b77e8c8b808acaae98abf5fbf7e1ea09ea1cac7f32f115720c53ca80a7e97d453307ead0f7ffaecc7dc3cf26" },
                { "ar", "4c08e777d327024b6fa4858b81af0346fb27596304f5804a401205354aa1c4baea4a28460ffc41fa912f02fc56516c08265c4ecd125a444d580191be0933482c" },
                { "ast", "2238312d9bfc359a33aa465ee771632b370940591760fdcaf837f5f5ecc27a1c9742665e2761715c3512a23907740d3b5bb9fd52d1b67b576930668c66252139" },
                { "az", "0ef1a5d7c5e852a6b268eb552ff34638c88a92398abef972ef6538ff396c049d53b5c2635a9b56b948638537df280c980b210dc098a0e2ce2de7f4f7791760a5" },
                { "be", "5c5097fa884cc5fd1c0f7707739142dd4b4b9bf1afcedd7c0a468dca29ca1e9ce7bb7daa1351bdf22a28829904889f996603634503533d849e2a2917976fa3c0" },
                { "bg", "1a33e51005eca182a0fa36865708bbaf032d20c319c74d77f32a277d24bdbb852858e321803a3af300aae24858733f07d95bc39fe8491adf507acfca8023a5be" },
                { "bn", "944125d096a1630007bb24fccecda9a592a0dd6a115923ea90d3df5d8efdc66417a874e6e336df2243b863b7961c8e472fe28f80b99a0eb820c49c8829b09082" },
                { "br", "d59f5314f52b932254f33efc58ce0d3348f57720710d3906f80dbe400547b79f631bcbc916debb6c79b576c2aae6247cddbb07100915022331c8499b8afa551b" },
                { "bs", "db1d570abb9790584f755c3b7b5c355d6cf7d5acc37d27dc2216dafce14068b81d4a22dc9891ea5be46e8b12a81a1fb145f63ee6377af195387e6f4098dd10e5" },
                { "ca", "6624f738e2ca245de18e439fef5ee28a5fc89e95923254f3a84aeb21832ca21d3f475650feeb4633b4fdd14836ffbbdd5678cfea09ed8fb66a047e7ffa594a35" },
                { "cak", "1db540d740249aac734468e1a3e030eb6ade3c743f2ecdde9ce232b215f818e154b611b029fca1eea26c9bc0be1b7308dd0c74ce7b641d2ad539b756da6bdd1a" },
                { "cs", "bf8e8ce732a51e094ac6024814e0cd638a62cf8359e66d2c3c201545255542c537a8dabb9e18825f3301614ca338a94988f6de049c199257847d43d82ca98c4b" },
                { "cy", "cfc248a69d0e520dac703a103f2072e7454e606be384377fc1b681bfe075e0b8cb542f6d4856c8061a76228b850c422a2894071b4e0337204f55dc1a54ff233a" },
                { "da", "07f848b413313e3745a18f3ef0720421de5c6852746eaa2fc112691db60ec6e83aa2284e6e262378f9dd35a6135329f9e0fcedeb2aac0ba0b20e69b0710b7e13" },
                { "de", "2e404df12da0a57e55560859aea015165a1e442576c9af0aa49c19113a8a935b44521a672d55f72bba71ad41992135e04ca5529bfcdf6266e2d63814de828482" },
                { "dsb", "85a33bf257b6c6e74d94abfca24990dda172620076cae9385c8533e9107e9c53fb01c7560c7cafa4ab0cd295ff227b87a89146747ffb99caa19bb10b6d70a3d0" },
                { "el", "5abb3a0aaa8f90fa19c48a04a8e7f291662266223f84bdb2422522f1b55da539c944d926a8bb521b63d3c0a97b10fb7de4ad6130ddcd03e3d43e8527541a1c04" },
                { "en-CA", "674e096efee816a3e735de20f93068a01cf6665b5521120a5b23b3a6a3c28ff9aaed220ee4dd18e5dede66545beb60b7863fc4dd28fb7de555077c916e04ee70" },
                { "en-GB", "92674e7f64bdb07173551852f61b6bdc5f359f6f1f4a3fc156f18768491757e8b8f1cacce82a4d8e4daf9ca33418cc1d732858e37f7cd3e593d89ed040a108d4" },
                { "en-US", "cbc3a17832edfb7df324b96faf61f6117126d83623274be9444d8c1782ebbe41ec70a7be49815b7b7b10f7d2c2007399e685153f0a6016caaeb7fdb64d782cd5" },
                { "eo", "a3716250aa4d0326d7ea6e70c92caca6f6a149e9524c5e3abe3e26202648b1202b9f21c4624561de4bdba7287313be54aff2714f9e139f64cbd80591d13ab289" },
                { "es-AR", "5290870e77c907375a000afb6d103062517713a068a8278b94d81d40ad6a7fc42bcea54312860ff540663f60e6c85a52ecbae69308f217c44501d5ada2ad9c28" },
                { "es-CL", "f680b514efba018b306e2184970c5517bcc1d6b8627679ad5d4033531b1a930860c1a65f1c01a3387cf0b6ac8c1491804132b443ae510e0b800377810783b9f1" },
                { "es-ES", "97e50dd0be1dfd1c3bb399ca418dcc04e684050e47478522730594c45f6ef04035f47c483e833c4c17cc6b363d95564f4d8d6b621731f2be851aa63eeb45fa10" },
                { "es-MX", "a73e4b0f4b4186f78467d0bcba96597aa3fef534452d27a110d164303058387f5b67c194830a10e3de99f14cf8fa19c45da12235f807a07a1e3552c7d09eeb9f" },
                { "et", "ebff861a6f34a36177f70967b2446d3e6c2231f85c7411b5a0e4e93b75546d98c5c4734472d397b8c9495f4c7fac4fc66d971ee154722d17f25ce5a96ed286fd" },
                { "eu", "1fe1a9ecf9f4a7ca9892f29be2c8ccf3aa736d76b661c25357474e8849f6204efd2b8b9be58208cd9471ad9547258eed4a1eb6d94d7312ff473293dfb78be879" },
                { "fa", "a990b0b8581e5637275c811eedd6ebf1ac842f732d578acdd0dbc23fad399db6ea025691c02c77fefcc429d116164acafece9ce919620f4e10487d14c3ced165" },
                { "ff", "076fc1c14f6b501b02e456ecc7920c8ed752cae503cbdd3b7b059ee207a017f58364c3e026435051a6a91925968a0ff9c0cb010842659a54ef71e7ffda9ca5b4" },
                { "fi", "30a44492c1dee9966f59d9537732d5627c895af868dedbf0d548b8979ac63ee65e378adf5aace32929755f1e1785cb8cfb269a3538119de3cdbe63829870ecc9" },
                { "fr", "94d366a3f571b6b5ff435da40c5c400962b484f6de3f6d7e2643de6f39d48d53929c92144d58a78031923faf242a5d812db879a7443f3712660cd8258ab88ad8" },
                { "fur", "6c7b8f3a864c3ad18a7044318e58de254dcc14fe569eac4232b3e6fb42fa3075b575b00bdb3f90390d5a8c70f43a3644ddae8d5b205b5c4fc550d4f32c2fe12d" },
                { "fy-NL", "ab05dd0f9fdeef521b049fb3dca4dbdc265f89d455936e107ffbbbad4f91c00417e4c2f38ab41c227161ce7699d5cfb74da252a6fb391dfd1bc693582a01a240" },
                { "ga-IE", "924a3aca4c15ab7c938f5cb8e1adb740b7f36cc8e720e8a9d24511c51fb0c0d2521bb8782faf1959aed2f8843185db7878f2ee067ed4ee38c9f32461bc42a170" },
                { "gd", "5698f9e2eb79ac2bad74b8e0820bbbebdbcec951139ea87904c0a4e16554ecf860ddd1c5b15de19d4de560e68e2c2cda6c480fae1b381f0c4474336d89fa5613" },
                { "gl", "dda405e29dfb2d49044fa559b2034c6d3141e1737c4d0b1fde06c694b967e2eb0e4a8b88209ce78f69a795b5ce92631834535fdbcb546b474b3ef2a8593c29b9" },
                { "gn", "a82e57077a902ffb63dd3aea02b612c8db4eb6fbf494d61a208ff85f025332f7e5066b6455280974da1c8b7505b470dcd1a76fa2e3be6dbb2cd123e4afb2f523" },
                { "gu-IN", "13e83167d3ba0ac196f6bd1298b344508890a959a113cb5c48d67e201355d9e2c1230129f942978e7dcc9de235041d4bb558150cd9d5efdff0b227999e0dd6e1" },
                { "he", "963d0cc5143235f1ac0e24b2e3a017da6b27c4e5b2d08004c5a3d7867df2e22da9a2309936b904629967d5385f987a9b6e0daaa0702d5a9f7ee158ad85af96c3" },
                { "hi-IN", "b1a7ddbc9786af4ada348eb431630654dfcd5f6b9ff6888794e317ed854ad03bbc0c185e840cd5ee4722afa888f4ec34be4b9f5ab6ac45f984c862f0e581922a" },
                { "hr", "5d32729e0510a19be755b2cde45de1c8447aece0b261f185f71a6590987a126c0ab7cc6571aa5dbd1b706bb10ec867090406db331ac7e535a8df5051452ddbd6" },
                { "hsb", "05cac1ccc5e880f9a43630936b454b204512d081c2bfaf0090de536e52083203407b38d3a308bac1ad9ac240970c5d5d3f998ff46395d8880620082e1443cb86" },
                { "hu", "9be33cc443928dcc9c8c93521a4518a8e88a74ab2ae5758305439784bf7ee4ceff1af19122f24de1128f86d2171fb525c609fc321fb41e8ff637d4bc6e5396e8" },
                { "hy-AM", "cf4d2120467c4a8f669630acbc324a2a4ec7a497e8c5c2b857ae802b0c60b9c5aa046f90294b0b64403812b0ca9de241d402b2f5b8356c5ad1c70ef90b84b9cf" },
                { "ia", "d53a156cd908c1913651b92240299bcfc9d4c0f0fcd6e7b6ca7ef56c214a72e408fa7e368ba47d9efb30f0854ed0620d643ce4c077c7f0b067fec707eca5f5c1" },
                { "id", "56836ee4a4612903a67124f38a07b252b54fde7536bbb3f4ac3a1341727eac82601278c31a805da9285d03a55233814c3120b21c72514cc477a097b3f17ad749" },
                { "is", "0ef5bf2c6926abc67e30d713932ff935cbbcc68ff50c84306e310495a365c80b5122112bf1922597a2b32bbcad8955b7064ec0025fe0cbb300530cd54a4fbe08" },
                { "it", "a3872c88f4b4d0f2de956450f19d5f65800eb161d62972156a48e7d2bfc6e7d6c902f571c9e6fd4c7fd931669b59d597ea59fe43e6cc9ae56f68a826e1c629cc" },
                { "ja", "a53b91b32293e87b9344d5a6625f3e85a33f71deb73eaafe2b4e9b9777a0f865009dcd257fc6be0c87e4dad1795e3d5e0a3460498cc176941e281242b144440f" },
                { "ka", "75b91d96490d68df0cdba1312b5581f51d7aea38452a6a0a638b388ef2ac6f1884606b62fafbcf1c6b103628ba3067bc4e9596e6e391f69fbd0c4bcfeb0b2906" },
                { "kab", "1270aa6aee6d419ce1c6c39339e48534c97aa9a66c5c6cf2dbaa17ed8a0d49c4f8c70528a649d22e24f5425acfb71cbb817c141fe17b083d455c1b935243d1c1" },
                { "kk", "a5d2a7c2d3860b56940141c8b46abe63322c250b0df29d2c26a0bb92752e4cdf6ab9cafeeec50603a12755026cb3407d2b688f89434bb2274ced06127ab5177c" },
                { "km", "d9c95f31b3867515932b44026cd70ea0eb8750f40c098606fca9a618fb1e93277c5461e734d7c62b4de6dde1cded09a1d552db3837181f06d6981fbeef4c8cc4" },
                { "kn", "c53186b16a1ebc8e1b11a0ccc7393254fa10d5449d58135100bd28dfb3fa0580b302642ea8528f29f225e4ab312b1dc69aaa6c50f236cad8f62a0861268fd8eb" },
                { "ko", "7996b86865acc73ef327910dd024e22aabae4a2ffb502d323d41bb28aceb4450163a4d3da9792cf824468b7b4ea58884ab7aae52c0117464c3f80093052ffbec" },
                { "lij", "58a53fc12d8152604e9ae0f3404bee3b7ee3d2f556931551fced96c30d25573e9f92d76a20a80b33827f1ff8296d968db58225847b6c66769365f0b116ec7a1f" },
                { "lt", "6a0376d596cf5474ba7d80e21cc9495a2596bdb18b0ec87c794e5c68e927bf0e5778d8517cb759c9311b1bb81d31500f099e8ce3d716feeb76774ba99144620f" },
                { "lv", "a7eab0ebf788905de02457dd2fd625525ca32cd6f2749cb5f97bdae32c100ea230c86f0b2b14a92b9b93119e712cf80c9735b2ca496b82bff4aac35e17adc44b" },
                { "mk", "0c6902326409fc5abb0444e381323832cf425706b6eefcc8c2c2d278fa9b51ebf471243ae4c9c45d0254e714bb730257923bfa39f96973625428a2b39502052b" },
                { "mr", "a2d1fb0ac3f8dbe95d54d1d4f6f67e21a6d3fea1208b5e097dca35a9d79ce9982e0125dfa3a8ed281ec39438d28e24203113211521264f93a607ae3b9cd60cf7" },
                { "ms", "c8d31e80f5f880d16fdce66e1d069b7bef00d559b88035f7e85ff961699af9462fcb1e3455fc49022a92f6ba2fc8b69ebdf184c51e73298b50855d6e3b131e85" },
                { "my", "a0a3d064cd20bc96eac0d8141312be2783df26d1b32d291cd2955b0918bd7cc7ebeb57368e682a054ce942a507b07e222ae1cd609491396be113ba0a447d43dd" },
                { "nb-NO", "665b6369ff8b9b62991626d3bf3110e5123010d1384b4e42bf5e99f8ff1c0b2a36ccfb9f75700bfbeb949dfdaba3b19cc5ac471589158c79c5ecada83f19564d" },
                { "ne-NP", "a2f38a5d142c92eac939ef3718c2bf9a177f0d07119cc3792fc957e74c592fb3c006065abc4bb144d54496eaffdb4d93208ae261f4bea8e8405847a486dbe401" },
                { "nl", "1bcfc277e6c07df00688b5b7c919134bebaf66c732613026172aa9889e146b6e05ff8a42923bb46926e9cebad9a2daac24dd9a32de1cb2a1b48a249ba9eb4b4f" },
                { "nn-NO", "89492f92a5595c18128b7b6b26ad1cdcd165487dad6e37ab6a509c1ee9860edb9642b1a4c03409382f21cdc905afbf77dfed247d5a2f9841269f670cbef3ab34" },
                { "oc", "9568ad7b63ebe76e537e1c27f5ee7c4e69ff954d618fc7e38d84b40e4d834bd2a10a58c4eb86dc47b1e2a11985e8be69d027261bc11daa49a1f63839c23749a2" },
                { "pa-IN", "bcfbed4b1c6635e701527d9563b1688af85f54a4acd96cd5ca255728a78e3efae8fcb0feac1ead26a591afe14155a021f8710b0e99a835b700e2088ec108c7a0" },
                { "pl", "ce0008eba7cb894b45fa781e05e92ca3364ca3bbb9fd7a932bcf728d1c02f45fbc71968cbecbff50b5605f7c753bebdb18575b95a31ab86eecf283762ead8134" },
                { "pt-BR", "3a5b52a79f5a440109436349f7479f3503ed91aa4c39c118ce0c30025e4218e052fc4cd763271149c990921238f292ba7c180bf5f6e6ffd6acdd13d341ac6e8a" },
                { "pt-PT", "01d04611becda4c1365dce97cc500d230e65ba1937291405476f00d5b563b593e747b06181cb08123e3c020e7abb79332a60e6c7a734fbb74b8fc557ee3a1f7a" },
                { "rm", "d3859180bc046c8ea2871f70332eeaf4df9bd1f78b7b54a30c89c6cc0a1302d149f96c68af744acd61510310d7f7544a4866ddc6b0e50f4fb592ab2d300c3013" },
                { "ro", "fc3cd86b63d64d23da9158fa643ee830469260a7a84d952207538e0c3872cb771c271e7f39c339a3ac0fd0e8177ffba23d77657dd90d07e682ec0f5625acd6aa" },
                { "ru", "dfd8411b863da5079ac79c02f6277870e458d6eb446407d0161a91d22e652c114444305e7f5b9397b23c20df00e4d508e511d46c87408b710f0bc9c863d465ee" },
                { "sc", "7235edcf9a3d4e6586e67739155f3c1d3e71bc85904428c70e6732cc02a942faa39abf3af50e24008759310d0c26a86d622e02fd2bd0940fe2d38f6ee44ba64e" },
                { "sco", "87138ff5b607b76c6aa59e053fea0e31f2dd789037137ee0f1f80e80abaee74b96644fab88ef9bfb3f4ce9db232aa8c68a1302cdfbe61d8b06d36dbb60f3f3b7" },
                { "si", "aa250dc4fe591c56b54e7e7943f54cc7258b5f7873af1265dbe38826b4ca7855fa83dfdacf2acf4a54b45aebc2107c709bddcab3f10d5c2a0d13ee4da73ee7b0" },
                { "sk", "197aa6e0bea0657e77ef2e2831cbdbdf81b7394b5240486d15d628d3a141d98f02cbeb776771a211f2f7553718a140b4767b4f57876dfed79bf2f3c669683568" },
                { "sl", "72a3db378983d6c6ccaca334dec17c804df26087b937bd9de1f223b293b43db3999caefcc6cb411cdf0a5d7535d2bbb287a8f1707959a4125dd5fea248cd36a8" },
                { "son", "571bbc1b16decbb2ac2a14c010a4534173f48bd6f31f31f2ac769cf38da8dc08b0bcd76d0dc9a3ed51a65cb6d2550d437ab9cfbc70819074708a296fd1dff371" },
                { "sq", "4aba7a4396ff836b56080efae0cdce7e6b28e3da43dcf29ae5e8180bd00748e23c8eb243fa1457c1cd8b1b649096f1b773d3a251af2befe9a34e1036bb8c7f00" },
                { "sr", "c665bde32b4a72189ff8bf1455fbac4b1790c9b1aa01c4029d9086a777c36a405e2f987715d6513b7d6bb7040a58cfba5b867441a4dcf8f2f894e780f0ee4084" },
                { "sv-SE", "2be675e524f2de4521f04e73bb20fd6795edd6d9e94bc6ab2cf794adf5bf09a709c6d0aa07e27370aa353456a6b6ea95e74b8852b5e0ed65d802be2e63b9fee7" },
                { "szl", "8144cd463b3298a43b587f8c373131ebc224474f75b30f9de05e8e410e041179ff7ae79bb69d8c624aec54541dfe53a72466a23235a03c7808e74d10bef0ec1b" },
                { "ta", "68b086e8a71d14815636054321c59d5eb5e88509ebec2d1b32fdf1317e3556c7b688d8646cf23d7fc3fcb88292bfb7c217bc074812bf3123e7991e05a2bb1bff" },
                { "te", "39e8720f7124b5a85cc45680e794e528d18d5e541ef479d1960d9db0975c079a6ea9aa483567fc3bd0d67c03e8a9ed8c0b3ec29962099add2704f4a8b0c98e51" },
                { "tg", "8afbea7198e476dca909ce1a54bfdcd344208702eff8a00a9e2f26dc6cc3a63771513e5dbc0b7d70000c25d77bec37ba307c2b0191a5274b57d876d46b31e017" },
                { "th", "f99dc4465b270bb6e9580fba21abe93fd56758acf1a5c8d70691b03d52ecfcb9ffdf909e3dc8456948c27f1ccd7cf1abad690016f734dff57ff9e730a6083b58" },
                { "tl", "ef47ad2e99a240575c6ca78ca8ea167c861b70460553376d26715e15db12c1206f3307b56ed55ce3ed6b03a957b2e5ad1630ce09d5fbdce2fb238e71321b42c5" },
                { "tr", "9507954e50d17228900b4548df3a7a8c7a8a9be223e6995afd4f01276b4c3d846d946c01d8065728c5838db0c56e274f3953c53e050b2b23306ff0c5215f5d67" },
                { "trs", "0caf87e3b044ed1d5f1bcd71aa35826e483743ccf05bacbf36057dc1d3fdd7129cf34a04b3e028cd60a81c556d206bc9a61187864d54aedbe546e1b0812983fe" },
                { "uk", "a924a1911b53dd034e86e58a65927ba2aacab953aefee59673bd8e4bc452f6e2b740c7352384ea0358b773778c70d31629d2e05fc4272566595f237d97c8b309" },
                { "ur", "a1f1f264adbb779b739594d70de5e41eaeb2e0a5bc159037a6453d16c76728a41f3a4bca3b020095fc8c72da17b9aaaf0de702ffcb3c94f1669435f682fb5a8a" },
                { "uz", "fb385bc01f8dedc0999a2617a87c96081c143b30dbaf9db5b4cc0b61e2e7755af4b868569908d4371db5d4e50731b9c8b3cac6e4f6b7dd3a1d0db5db81bed76e" },
                { "vi", "aded15c4562121c411cf03abc9026edf25708387b5a62a124e5962608e656a51cb48323084b1d2dc0d64cffae0d5e554bcaa01eef2751295528b4fe56ca14bc6" },
                { "xh", "b7eea708489dc11cfd0a319a456f755e43a94478f4818c111327aff26a6cf51b3a2139270fc2d1768d50fd263598ef1352f3ee0e96048bc67e58960827f4ca0e" },
                { "zh-CN", "ada78273e9101c42081e0729849f0c5875dffb3546e7e487b2ce84416557406162b2fe6cd27262613b02852a60bd3afa9ab34fd8c425408cf23a240f68d6bd3f" },
                { "zh-TW", "79edfadc5ac81ac0c90c6f79c2898cd95a3e71fcdce6d47129e4104f3b1e28862d985d80b962c20728b27d9f15447364d175b1c071281c9d785dd7e234051c24" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/114.0b6/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "c197287952c1883ccb6227605a7d57d8647e014ecdc54efe1a61e83da3227c8415f917ffbb60e0f38fcfc8e5113214bd3fe6bb2dcfe59bcfa41770d388bdbedc" },
                { "af", "4127e61a92b6f7da4394aeec5f0fb77222b9653f8035a6542aaf4396e4d8dda874af0719b376747139435e0609c85664c955003466f10c3934f4b517775be16b" },
                { "an", "df10488ae3d0cb337228e0d70615bc3deb120eb4b1e28191c548f55d67ef36f022553a0d22aef51aaffc1dfc5cafbfeb7dead694a9e67d79ccddd19278cf158b" },
                { "ar", "8995e8c934f9f9735b161f90443da20c09e5bef7fbdb492e58da191d0382f87cdcc65a836b118b24d24d9bd63900326b447e35724af7876bc6e81ae6346552cd" },
                { "ast", "995e1b9fa02f20b2710e836b27682eabf9477066e3727087bc06b9b61ae7a6f266dfb9cbc086be767d0d48ed46352caec6d40087488712381ffb918414b4cc05" },
                { "az", "e76ce4e6976670148f45ccff3a008af21c03717ebf25f851b3b78d0dc0d43a142d1675c9a2412b78364a54dfd99a93c7ed4fbe1d3a747625c58cfa58fdf0f41d" },
                { "be", "31a5809e6a442cbe944359e55cf48fea98b807e315b870a034792280bfa5796d08fcdabde60070839da48ac16cee4627e878e975540ada438b6602d96e85c22f" },
                { "bg", "1def6a594c1080e60da0d1dd0c4a79d06f73573d875f18d11048a9785de2e26cb1267ebba8cc38b36d138cc81c1fae23c171ff8141351bc65357ae1406a808b4" },
                { "bn", "b7d2e9309a96ee8978f8531baa162673598cac8d51aa3dd79eb7b5bb034ca9e6049b9fadb4652ff6d0793e0933eec900fe2912670b185ae5aa5f409929549de8" },
                { "br", "783b1ae9286f6dfae3634b05b9dfdd6dec3ae13b893e86782d96a348ce6cf3e38f5856be929a5702012174ff6dcb46ad87e1fad20f1e85559a07b74cfedf8cab" },
                { "bs", "a57dc805ac4dbca3b9528ae3c54abdc2f1121167ce6b8258bc9c9cea47f7900bb19e1319b06dda5f208e18a291547bebfdee4c1736772fe972dedd71b5c80c38" },
                { "ca", "4f1e1a4ca1e12f8777f1b55b904f4c4cebaea2dccd1bf21c96ddb93a94e5b3b5a5e79ed832cf9e5cbc86b7483192b1c2d2fa3342c2daa7547b0641e8a755fd45" },
                { "cak", "a16e525c6f408a66b3ff8e32138fff9ed84823cf379ede84a8f285cea5877a72694245491e7c572abca30468577b670a2389c1f69dc5984888a8a5ba44922bc1" },
                { "cs", "0fd929a9623b6ec5923de1cd026d2f22af176d88b5bd4a3f664f76928eb194570e7e4a7270c2380b540c7be14d466daffec0252f3c82b758cf19cd6735d99c5f" },
                { "cy", "a96971f106fc81bddacba75316465f9e9b31162121ef70238073e8b222a8b64b6d88ec6171ada51173334f7fd1ec2222e4760b2336f8f695303db3850efcf098" },
                { "da", "2fe7610e5d0677ffd60cd9403e00584b13bf0d6784bab47a01cdcd00d647ec87188926f3561d0aacc3d5c7736ddc964d6df29440a6bcce84485f7900e663f862" },
                { "de", "723ea149b8e3714ad5dae10962a629b9cd1c5062dbc3766787170681308fa6772cca85f7a3f7bc734aa057c278538d2c9b8fde493d0fb1c43d6d461268970e47" },
                { "dsb", "78a81edb7abc8ea1635fe38b85ca7b525f42fb61989384fce0a864cedb4b8c5827ab313b2810a6d654d18b5fb680eb409bd37e572a3b7c4ffc3d838a5b607a28" },
                { "el", "4677e8544cb08e1b31d42ad566e8dd591a980f05a550a36a70a5c23058472eab9dea2d6cdad65a2e13793355539e764b2ada1cefc0edb451867d471941f75861" },
                { "en-CA", "7c15a6da069fa42ab0969aa6cfc07c70b0695cb704eb17731df247f30f3c8357aca92e73279cb54a939bc28cc7a32590423d336b9ddfaf1f0a9666bc633cad7d" },
                { "en-GB", "b40f3fb2dbec4879049096a8065211f75690d08d4de911157bcfef9da9a239065614a1ce01ee47365bfc77321f39325c0bd7f4d3641e4f54bca19c31a8c8d5f2" },
                { "en-US", "dc73f4560721d3bf77acb3449ef0787e34d4317b1b3a42092f0826935db4e51f685439a0f70c3f3789a0a7b7c781064d6db36bc082a3dbc27b7998afd808ba4c" },
                { "eo", "bbc1f18358a34d02259a9f9c199c0bd529ef91a5abd204f262edc22f7329aa7f1c0263b83430d3ddc8cbd0adcc3f3b43298d6af5f1aed734239d96f5c57d1cdd" },
                { "es-AR", "a7897449c64b7108259eb060db060dcfcc8e5178108fa367520ebe1084bb3f1b55ef7b952d8279967a84c391841faf1cba160bffb4edd3572616ab848bbe7feb" },
                { "es-CL", "d966f44332c5d6d62067f64ac5b2143161bfe4cabbf50e19b6c044dc1ded66238f12d808ce52881e4096c9a6e2f3854f8cc8fa6d39884714004655e314a016d9" },
                { "es-ES", "0bfa520f41e379dfd815097cb6e6b06494d3244654bdcefb8fb7a9ab679c3fe3414024d47f478a87e81219e65d02949dc178c8d2731feb535b9b45153027b7ca" },
                { "es-MX", "769388ee023c16ccaeaff96cb4582495dcd5f23f8c86a060d8d4e824d231bb9009428e567f5bb23fe7a49ec38339ae1cb1210b7ec8f6ae02196519e1a127b9eb" },
                { "et", "795482b3424ba54283fa774ff173b2c7175b2700e6d2d4e1f979a6b56e2c2c4010c940ceb72d63a0c11ba5011f9b8005ad151d2cf8a545be0f59d7d89e510aa6" },
                { "eu", "a753a5e465aa29954fc94a37c58c0eb3517c27ea0f4f15073cea02a766fa0bc139e0d44e1c293108d1ecae3a31196446b35dafe274941ccb0c8b97de04d2ad93" },
                { "fa", "da4ae5830a3b5ce12c2ee2980a6654ea3d56c672fd720a695eae0e1ec6bd8b6a0b549a93e9342109855d9a4e295315070d96f5c0ff3814da9616df97dc1b4556" },
                { "ff", "57a470d1edceaa44e26baf1411b16cbc89791f4b044a787806a40d3279eac140d1c8e63e37575c1ee317f1a009c6a0b8f180d924beb67cdaaa05b6a24520cf01" },
                { "fi", "3876f018430d91a5d67f1e78af95306c460badd04d13c5190a8347dfecb40666d89f57d59f135b97cc40d528a7106ac0f6a1070500ee8dd2e91f1a63cc0eb664" },
                { "fr", "9bcf700a68c1263852dacbd56d24e173beafcb78f30b2e570cd2b4bb01389a64bd1f811dc359c7ac12a33b3a89a2ca9be58089a08ba56bc7fcb7ddaad90bda22" },
                { "fur", "ae3f27737573392c3f7fdbc31a36a6b119f03fd6a6b958a6cb3d496f7ea5011659432ead7a05d289bc75e73fa8b91ac82970f45aac9e8b0a584f155a00ff6402" },
                { "fy-NL", "917851c4bfb2f66fe00bf522536fb622003b11c13ca14e45d7246e24416399c916250020e189d7c151190b2b7c126ebf8eba4a11799c742bade47780afa74cf3" },
                { "ga-IE", "3b7d98f33fa2eaa483ede44d0eb74e07e32a3020eb42ee30ad570d1e09d90e45624916704bdc3bab1a37f0b5be70ce2664fa0b7c86e05fae8b86b500784c0dad" },
                { "gd", "f86d029b6a34d7d4c08c26f81e6c0ffed0e240523eda5720b18d7b51de1439ac5366a7c504c06c90dc1b936496e67c3c98470e1c2d16d7134e4c6fdb50c8bb7f" },
                { "gl", "8e11449d289fcbed752ad23c92329192879547aacdc29907a6d17f291896eb723946ccae3d9772135e85203f3cb8aecdfe17b1ba5813b40729151febeacdcf4e" },
                { "gn", "90c306b0c6871d0bf11cc48ccbd783a5eae1a03e14d883df092b96aca33d5a3bda45e7df2d17b6ddaed17c3bd1d85c002b306cf0580cc14edbad0723ad6f170e" },
                { "gu-IN", "c83c342388009f14eb488ca176af0981c1ded22d25fb10b0c0a29e390f0c2c807553cac60a3f77f6b68d89001fda188fe59796ab9cd273eeee6f57953324f885" },
                { "he", "cb21f4e2b396d2b38f23303dd99d8fb18e60b1144dc7d7ef1b2689ce27fdf3a487f8f2dc5cdfa3fdd6507ecfdd9425b1b5902c3f719a94148e995213a67a5fcd" },
                { "hi-IN", "04cb78034517746e8cdaa47c823d69fedbd7f508ae2384756a888f1c6dee086996e76d1a0774173eb7da55fab813557bd072d4bfb91d522dff35e28ecf583a83" },
                { "hr", "6c61e1511a206c6b219ff55685960a1861b90f79e404691031cd0579bc429526e09a591bc5f30c23e4919b2ca1f45ad7497d1ab6ebc28455517a70a41c5153a6" },
                { "hsb", "0c7d5fab90318b5b483bdea27145930beee5a1d07586f2670a354c52ff81c682fb0b65d24b779e03c43d37ad87eeb4c8ec2bd5f99adcac6b67dad8c1caa54ef7" },
                { "hu", "cc7bc75f4332d3f39f2429e6d8c926f72b81bc79ac0001d0a9f119d1a2728c7949f6c0cef80ad9e336f3a4552526434299314c29f8307f01b1a269775df8c45a" },
                { "hy-AM", "ae078a86618d6b0aa34582201a422a198f004d9113423671f8f02cab84a5bcfcaf0029287ba586913fb25b5d0d61fbb625b7202d444631c123705bf924d80fdf" },
                { "ia", "1e155c6eeb6cf10ce7af0e57059b1bbc6a8c0b59f3f9aa4f82added9567aa3ae6c62ffd6f8f2519dc05c4dd749dd147902e1c0aefa3e1577fb5f8f92d358425a" },
                { "id", "c6c98eff2e6967d549010627b6acace837e0c21081adbc0ba12472fbbae9f6243b1dbe535228df1e9af059190dc37cce1cd6b90b90a6a122650577ffab488cc8" },
                { "is", "1ca965fd637aac095e8e93a0b1ad7da6713aea702ba3a57bc38c5ad3bf8f663cfbc875d14cf75542382f8898ccd1ab717862fc549400126fb25ce627a5e867b1" },
                { "it", "c057d6d1388a9805ec6ee23f6de9938ba578de62440be823272272a344ee3eae7c02a2b53f6efe56990c27aff0e5f760a701227bfbb2addbe86b049e9be439a1" },
                { "ja", "0d44dc984356e016e1f8c3c81e7fc5be5cb45d308742f1f55a2b92378f94728dc00d162f548b22f4c7bfc150ce6d928b45b312cd64e50604450e4637fb4f819c" },
                { "ka", "a9b5220d1b8483fa81b29f135330cdf3dc580a4bfeed74cb24c363abab2adf04951b038016268e8d1bb08239f110fdb918dec2ed917e7d0366034acc9f430c56" },
                { "kab", "3b17b86fc3a3e18c9ada21ee1edb435d681be1fd20c4f5cb597b5fd659eceab88a4cd934eb3ccc76637c663ade06ae390feb59ca91f9ce0f75aece0ff4dcdf05" },
                { "kk", "887bfc74a25233bb7e019b0ac662318fb88997e3f30e4ad9f95d0a089d336a50e513493c629d5a94900b700ae53f0c0a866ba6b7b7a7d4b0ba4137af37c40679" },
                { "km", "1c2c95a81a9acc3fd431e5351b4b17608d4798a8b8285efb473ac7d4fb170f8804280026ff81c0c2e7fdb555b9887bee293303060e530109ea9bd488a5915d88" },
                { "kn", "b4046e1b7fe14977091084c4e93d75088306af6dfa9c49746a6b8fece2902e5640e8621f0ca8ca71ebc9b3e2dd6625bde14f65d700c4b67d75db22b9453a9426" },
                { "ko", "63c9e6521d68dec8af53014d48f95119694394f69e5cdae7b754fb3d06c48cacdb0def31b659fcdd77ad6a0e96fe8d2cf76cec770da54fe8315b5ef688c2a143" },
                { "lij", "67b8e0db7da62dcb987fc76a987f1b7c7e6187d65259b32d327f036958f8e70f73d9c5bc7089c9dd26d9e889a541ee8626af55856f38e257b364cae6a1648a9b" },
                { "lt", "fbb83a31f8560f62e1962c0cabcfb5f0faba77a1e1887c15b1e2680b4295e887d189031d4b8da2ca26dd1e33e6f252c0cd6343420acb33c29f2d640fcf11bc36" },
                { "lv", "a35a3d005fb145f6d6de48b67de6e911d54db92da9481f35c49268c704ef9e3da38509263672e7595a1550611134e58d898aeacc28b7f51d3f4863dbf93c3e73" },
                { "mk", "86c8c589ddb0bd23aa1df366e715db277fb589309771bcfd27d0849398ac2e8812589c08118a2a22f351b3823c6993d6782c0a9e7699a3a0af0e0dd69391ec4c" },
                { "mr", "23c1e80ffa31c9753a037222a0cc6ea67c49830f83dc576ff58257f778c3ec0b09559a56b264ce4c4570b4bb85e9ccbe201d43ffc51007778c3efbd2c1d81f02" },
                { "ms", "cc8cf15e9250841a2d5a2a60ae70b2a936d588cf454a79ce89a2139cd7d2d159a32bc056d08fd4a8f984f12990888227659767d77aee0239635be534f74c0cc3" },
                { "my", "4a90362b72b208f059893667f444dbfe75194d8c78c6b90766a673ff2f6fce330c0ab2f11ebc9663fe57c09db00293d2f52504cab345abe285451774acc9c7a1" },
                { "nb-NO", "b23525ebcf819388d3f0bdd1d79daf30f656d8a06dff020ccc8c25201dffb7f485b61f9eec4424f891f743c0384067b1c94a74e7808caae4569242be42ec036a" },
                { "ne-NP", "5fd40184d180153f392ca561250829112d6b86790762a65a1acae146bc2fb23a27773e62be0278bbfa13e32d902daaaa6ed6166d7e33b63679ffc18a7e58972b" },
                { "nl", "f8f425feee5fe0fd57b26d15497096124d606231e28edcf0aa4972c66a7e05cfcfe8e2f0f4db4f69981c24ec74debeca363f4d2711527cbf252d3aed9347d5c2" },
                { "nn-NO", "0514a1f47b089497a5d894e92996d7fcc1c74e69675da454a0d1e7772bbabe3c778b6ef45a9ceb7af0992d64203957a77d5e7107b8dbbe41f8bbb0b311694fdb" },
                { "oc", "b08bebda8dfd8cfe2ad194138790265a56b080f165dacc39dfc34845e8f6ba998015d7287d5dcf568398f2c119d87b2c00a9179dc2f9d9b1e0830ee1b12e0908" },
                { "pa-IN", "e0d62dca7dc83f35fc1e8d5daaeefbb2c43cf32d3e012f2abcab5c69515f61ae89fdafd83ca4f82c8bf325d282fd6306cea67c89d6f08b9bec0666993b083fd3" },
                { "pl", "b0e3db9667f7da22c32e2ec761d7086f8c734bb688abc787bb46fc0e3b1875402d79afa6bcc481ccc378c0d219bc14708bad08858f8ddfba95030da78f380591" },
                { "pt-BR", "23ae91884e691ec0e5f1c68c2673b48832f86b622127d79f8b7d5edbeeea077e4b076b8ba06c2d34e40a490ca9e0e1465791b30800081db3733252214b80b5c9" },
                { "pt-PT", "518d1734b369ac477e1a7569b75c3534859d6a34a736eafb47b098473fe45b9612eeaa9d9c9c8a4f0e3cf45c1f42893a23e1b6c88af275d1f820d5dce247c9f6" },
                { "rm", "5f12a5b64658661987da3b0c9a59115a84fda1d9f75d1effcf5a77aacc1cdf235655cc1cbf67808777e0fdf78a422641ad607907d2cf1cbe5cc03222e7dc9120" },
                { "ro", "28b86fb91e28bb14768e031fe508791e2cda04f275ecd3c927ab48bf8dc06bf6bd26e9c7d636a1d9dad5df131122cf7d1d07ca79beb1d880bf747ec0e1026f0c" },
                { "ru", "5840b3a2c9d2766f459387e013dc6e6e04d9118baefd8321f6e3ac67f7f2e2b5b5e18ec077f5ad1491b555ec871fea1a5e912bb0746c5ee11f116840f598917f" },
                { "sc", "21da4a0c051f298ff4fe0aeb8d6cef2351dee8ea5194e039af2a85d97ba5133b8044a196582e82007a9ff3dae8ef306ed556b362f5a14d1f620df81aef14e7bd" },
                { "sco", "54275758d9b0973cea9cd23971a8fc43fabea9b2bc674b0bdcabd8f5b98d1d47b775c492e4145d4d259669857f847607651dd2899e62a4c450fb2f0f5c21d7ce" },
                { "si", "8c8e90f80d23bceb6a1814163687a0855e54aca0e36a51a6f88db7b6ecc4d5bba8788b596cef607c4ee15f5be054437586b2e8a0a82ec81c6efeaf08421cf30d" },
                { "sk", "fb0bd2c99f9458a1d0fb22304253c4b4aadec368103357470c2dc71cddc5e6bc9f3fa58f2062b6d106dfec317ac79bbccf74b3c38d0964dd5aab237037817d8f" },
                { "sl", "5aae683ab6218e92f87cc57db3993bfee3a86a7ddfe07e323a65d1936e908508d260a803e99050dfb1022459e8f4e829ab36f62bbe4fdb3cb1e896b3c9403518" },
                { "son", "6483324f1f5f33eaec0e6744298c0e326c09b2b9706accd8c4cd0f450bc8e1128d46c3e92b9abd9ba6e65d2a67de80d3fa76ecb9da2ab0df23546daf8f49e00d" },
                { "sq", "ea4c8a332e3ecfcb18e5915ab9940b9de6c6cca1a6a1449ab3eea752bd74170d7fa68b0e45fe0c6add4c41080f6a880a7748835578be18b70f8e3e2fb5bc2705" },
                { "sr", "e22114fade9ae36a6ca06a84d3bfcaf4d6b1a3461ff426de15ebae4bbf8569960f197879d719daf3799bc821dcee84651cad071dc906ee23f8b6637836dd55bc" },
                { "sv-SE", "f406beccd1bbccc1fc6fddb58f8427c02f65a40cea33a01febfa4477e0e149f8381cfa95b0d15c16f00508a61682cc53c03a476a2c68cb7abbf0d00dba921077" },
                { "szl", "55007100877088ce3e473110e0e6dfd7e5b386063e5f8e24c4c2b59f856ff57b446d523bc2480b76061589770dd6867ed2362942b39babbb3d9ec043d166c446" },
                { "ta", "6fa3b80dc059808c9314cd1bc1b5debd686e1f133939a7e11dfbf3367e41626edc7dedd45722e15f1d234083d059457bdc222408c23d89f4ac079fbc637397f3" },
                { "te", "c2fcbb1e8a1859399636a72f7d54738b95609ba1729f963aa4c7f19a6e210df5a29137b419517bccdf6b9e303e133efdb26d8be5bc38cb79ca3e12f4f01512d4" },
                { "tg", "185e633b6af8cd4f13a821fe49e7bd5b1183ad5d44d84614657702bf821bb50be6bebe77a3e1a3b4b4a0be21ab5d75758e9f545a4a838cad71cba20fe8ea1516" },
                { "th", "724b50fd8d26ba09981c2fde3919d85c2d32e6da53bd3f2b1f6efc7f48e209bae0165a8944dccb1f3b74eaf1cc2a79cdcabccaeb151d80ac9d6c13575e8a783e" },
                { "tl", "cb48fdcb19200181d0629746911d24ac81dcafd22807f6410dffad38aca0022d23434ab11216f043c6975eec7f030b03fb5c6ba83aafbcc750e137f77527663a" },
                { "tr", "5948ca7c2d48aa1ebe14d078f22acaf1a8dac3b96adbc0bfbbc97f24bd74b8f18d561fd68ea306b247c6e3e4cc2ad928f4ce256d2dd11668b816228125cee91f" },
                { "trs", "60b8ff21b9156d4c49f5280e1593c25b8d97743546b70d417f9292805b771a916e96a8d3c56ce2eb8c6a284883aed1277ac85c71b22fc763ece2643f46a63969" },
                { "uk", "f9c929c6b57a23817c565d64a4b1f69d3ee3b9c857111728c64edee3bbcc9a3f0c28871a11daea2493a3cd7ca6ba105433beb67e2eeff954706d6963a5ecf4f8" },
                { "ur", "763bbc25af2ca4cb22726330b711ebec57549267d9490460e2d8b0d19b21509f37877c155c07448077b2d996e76983ba3e8dd56810cf9056d35a550da647fde0" },
                { "uz", "844a5dcce538bd3dcf210c9c3a2d92aa33ab405248483755211c9778080a13286bdb9f8f8806a8b595e9b0bd4c6c6810f5832481b4b9d1ed7c5f523e9b27d3cc" },
                { "vi", "19bd2f8a93247e8c0ae8bc2e40078c58be51ade2aceb0169b1adc3700588bdbbbfad2a203b708c7f62abe5f0bb7cf3884fa5eff9fb7f4f4c4f4830cc3cc098ff" },
                { "xh", "ae8a81c071b12a497e885c7821378d30c5fa3dfbe035026f4be039c1e0f7da3d47ce0f5bc064d36ba13f7d3e7b0bc8d1b2aeb9b76fd0321bbf25d2b9f5be7e08" },
                { "zh-CN", "91f67c5ad3843b1d49b465b1cc11ca574e0fa020547a747bbfb9f70fdaff48b163bd297093949f076b339f54163a030d226c73eaf2b36da7b205bd6aedf153a8" },
                { "zh-TW", "8936b1d582f0afc00fdb92eaa71b8d02acc490572da8808bfeba1a7509a97367b84dbfd7beebd4da970b2ea68d32fb3412082e7193b41efe0c4101c6f81ecc5f" }
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
        public string determineNewestVersion()
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
