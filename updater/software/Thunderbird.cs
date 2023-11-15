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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.4.3/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "a446abe44d2df040fc5f60263c3211336bc96484fad10612b83e77b3a01200ff16425945be4fc325b885342781a3f0b86b57fedc2a78f1d396273e862e6a39ed" },
                { "ar", "12d1e57420968a6156599cdfa54da993261dfd3d47047dac527ec3b5e5c2c4635560ce3dd7ac40e7a79eef501298c086b76158a81eeace32a2c9be9e65e11d51" },
                { "ast", "84683222ec2bf94d89d11ff06b28b3bdef2f753e9c232a216e22a1bc56b4b6cd0e98604d02d7b8bfc98eeb696957e1ffd666f7f28c2e8eb33591a3209fdbc62a" },
                { "be", "5d5a9a95aac3774c71bed3b5812ac9e1f9778df294aa9f31628fba8bbdf3c0548ec70117a91bbb1402655370f790468c7e40d109e940a0372d254272e5be8ae1" },
                { "bg", "ffa07ec7e2d892f6a00ea6f1d5257f754a08ff45f70bb87d51b2186f8b8740d998de5ee800c435f557bb054dd6eb748fd924794c61989ae976e542a6b117ecef" },
                { "br", "5c8ba6adbd34706f36581922e45e1eaf031c011534ea38bfcc15fef5be131889f6e3f6df74c80b17c1387f0f999a6101addbb16227b0242028ae1ee857726be2" },
                { "ca", "da842d10974b8396064ee9a44d31962896886a258fec1ed258c5369e8495c8909c1d618544b457a0abcbdba4fa607b98ed326d9d95c78a146296538ea15cc53f" },
                { "cak", "65f41303d2914974195ddc7ef5d96dedf3a68a9e80e6bb4acba07e9414a67580c6fbae88a49d9c32a333d85d737ef02447cde15e9b03b53a83dbfa3a330a0fdb" },
                { "cs", "6e6ba462fe8d02dc971dddb8e20890ae03c78d8f24f1d5a3b49cfcb8797a74ac9664c33904f5e0a4ff92b596cbdc518dd85867ee1ce6db4c34685b489f51b831" },
                { "cy", "0d300aa0e5f8e3f9ae67f945190374015e9bdf440aceb6ecffd77a66ec7078955f0f5a87176cdae1977e598d28f91f01d111eb8f680f6c1f78f843ff93a8713a" },
                { "da", "9065e8da48b93f6e7364c3f77a5e037a74aa8e6b288f9cd2321d7420507b50d09767c70eaca1b99f2b1d960736b0a17ecb37caab82af600159ab5795345fc32f" },
                { "de", "afd5dc1c1c000599e1c0d08c8cd65c3467b8a0cedf83c13216aa0f1243f181899883ac64ba96137c25855a5ae8e06b013400e2923058cb66fe7800d69c6ed17c" },
                { "dsb", "dbcb9156092d89a9bd45f526dd68129da3f67af681963ea7f6ca697879f1f49e4fb4969a9a86c7ac9deeaebb24c62513ed3bd3ba90b550ee78af2b257c280578" },
                { "el", "09d004f3334335f62cceb76554feba357d7a4cf9d3f0b3ead8f5b9ec47485f71da300b13d132628c9bef38c3c89856e0c5a7ef0f914c9563b9d5574790e22d98" },
                { "en-CA", "0806669a18630f9258fbae61d766fbee31891988266a8ebe11ace82466a0cf0a0147c61bbd34c5a345830fd847b637864629a9bb5e0b830f412a9a4789a73e66" },
                { "en-GB", "8f0f57a94ab9ec1b1d0b6059e25eeea60b1e26f56d12b928848b5bde41866c892db51dff49e7cfe67cb79b33779fb90d50e96c8879c39cbd9a003e386674a7e3" },
                { "en-US", "347cfdac888bcf6ecd765e16deb5cbd64a4dbfd1eb318ff2f178b09e5dec2c6701fd7abd019e9b2a61a8f0bc9acd84f381dae6f2d2aee98abd4fb0e23f4f2956" },
                { "es-AR", "cb552bbf97e06956655af06d26fae14cea5dc778191659ba0ce70b97fad1a39238958511f61f1bab0cc966832ce2d432a879f680b422052fab21c88f2f57338f" },
                { "es-ES", "a1f81ce0f9133650af590620771e140b482a7e35a2fd5a185803b19d43ff3163d742109fdd91d5445b0a22e1a474473c21ad063f71c34503ffa8f4cf15c1c9b2" },
                { "es-MX", "6114545952d721c45e92bee49876441d1f3b1e7831b2b3437f0f4fdafaca16fffaebd4d77cf4d32def6c5c2e014294baa1ed19545af26d7978524f48449b446a" },
                { "et", "526e1eac68e836b85686a83487dcadf7861ffef91b6b4d3b717c79cb84e2717a9e49fbba57e57cf4c69eb1af96c871f93c890218a55926ded96a3ab0d04a9b67" },
                { "eu", "98ddaefa4914857c90acfe74dc3ebbe66b9d0959e5651eb8530ca995b5d7bd58629d3067242379cc992d8abef4af1924e335afd20f4df22bf5fd9d905a612ce6" },
                { "fi", "144baf9cbc2606f3be8f766472e35964cabfa785f4853c569fc72d203ba6bd93312fd697812bde924bd325350e48c09ea166daf734a219c76fd47187e98642eb" },
                { "fr", "d2f0a9cd5b3bdb669297ba0d29ae07da516212fbb73bec41163b19dd152fa4e1ad7dc0c00a7d96515f10b68fa341539a73eabc4cd90e0c716045a216fff5438c" },
                { "fy-NL", "dca9a115751cf0105eb62f9169645bf141245436c7e3d902396a03ebcafbceb91b7bc3a00e6d4703f2e6b07e98268b8daa1431ead43ad133015cd3dec1d26103" },
                { "ga-IE", "2a9683554af14b0d6aab30c8ff00146c21312ccadaf579d388aa817cf871bdac872f7c47bfff0d75ea9c9cc38da4521d056b629386e9fb30368e06f0cc06a2d0" },
                { "gd", "cd9518f8b54fdf858ec599802642e91c85a6bd299a9fa441e32b0bac25a0c887d6879a40163ecc4c1db3a3157c3a77c2d3c11c0479c0b796dbde09ab88f6f2f2" },
                { "gl", "a5bedca808c24fc1fbcaa5052182c72e1c28b49ae20475930794001ad42eda2ebcfc13908c7823aebe06da7c221c17d4433212ac4dda509af65f570b1731a035" },
                { "he", "e5af379a2b8098d95c4b86f6af99ed83d68eb75c89dddac7edcab07bc05317a4539e48435ecb404e77bbab3658d2dac1785f8733304fac3c99dba18c7ce6d23e" },
                { "hr", "f2ce6d9de6a0cc85c78dbcae76ccf8a34f0fa7124495cb15adba623f176c2acb2d59b12fe1766c294666b7510387edd530fe9c3e1b7404e6bcd7a84e518755fc" },
                { "hsb", "04314c1cd7d59dbf53b8c42a8848f795f426fb50dfec6cb54d915295fe2f5e7f3f45efb0484f2570af3e23851d83c8388302715fda93e15202bb59d9013fb063" },
                { "hu", "a3e46ad10ca0354a21192695fb0708461477e961a2acbb488e9e4059b2e978aee6f09d750882d96e2f576da2e46f589021d63d0ad2a369d32169c543b134ed7b" },
                { "hy-AM", "c8db61dedd5ba52a8cc2f353d9031c23809eb60402dbe682a5ba0acd63d40b279979b45361244bd7343e87bcd4ba20d6c62ddbbd1a7720a6afb7f343c48530b0" },
                { "id", "30f65d1461b23cacf7f8141539a11240efdf14bd9e8af7bdd4bb35ef24cf61a74aa77ea4ce6fcfc9db1c930fd4b042703c7c69a0389015af912cd43696e50d27" },
                { "is", "47a103d709bf26d567935bf2af0497cd724bb7bea3a7e0f87f0446fe3d3503cf00c8746df469ebdde9808385056bab30e12b8dd3bd2a8adfd038ef4b59f3368f" },
                { "it", "aa20a5b187ad4f007e3dcd8731ed79495e623e37fce8521189e5dd4285b200c1fc2e1fa6c6bf64d88283ed8fb7083e1f4c70c303222a1cb01ec2131980e74c35" },
                { "ja", "ac5ee9e146fab7fef1bfdff626ea0b3799a521ccb97acf5bc5c18aef519810286ceea8399f6150fec3fde823920129dc5994138577351166337dbc6ad2a1fc14" },
                { "ka", "15f65fa0bad1739d69f4d5cfd7f4cc649f9ea3463e918b4c6c5dad7a96dd42c5a811ee39fdf0ec3dc31cfdfeb40db5ecf1645cd0d77739dc38ddc49472fafcc2" },
                { "kab", "506b8e078b5a6de3885092345b585f72faf994e9a6b81b6183d00f440d3a8f9a940cda30851ccf28df0ff319eb47b459c16f71c441845c93b38d2da8451c936e" },
                { "kk", "433d5efb3ca9b3728351b6fdc8ba33c88d41736e6375852a8d35edf00fb3f869c6ed1304b01cc8480bd716a0fa50464ef9aedfa0490a5e6eb58f6fab7151895f" },
                { "ko", "6b597a8533523554e5a1cca99de3acab340d7fd260c274d2e25096e70b8b42cf1c9ffd20321500bf39bb276a485e0ff1de3c1f8ac53a3f76863592ebc689c122" },
                { "lt", "580fb24a940f0de33413764c751ff0b62ce8e17b1208e7bb278a67c51eec28df1ffe1c5205fc2c14a0dbdbd5acf66299c980441679e7afaab4dca99e398d4bd8" },
                { "lv", "285e714e6b4e267ca74f29b69fe86616450b6d8035838e7d3d996de7178905143831bdbdf755abdb828aae1e3567bf50bdbdb23b6c5e56884d2000bcb4db5b22" },
                { "ms", "c8489c0a111e882e591e021784dcea9b66d3a7da63e469080827f54e81994578d745c36a7f1e0da303aa085392f9a84c067a50c941235d9c2be465eee9d77307" },
                { "nb-NO", "443fe0b5c8bce2439e66b6bfa4a39a9aed98755bb6cad792b6b2e36b48a5418c0a44ec1f758875170d1e7a0123eb15f8abe15e41fc54e9f2904c7b7932b4b190" },
                { "nl", "7728ab0de8f8c79da80da51e49280a71b52412af5669c6996351e9f7e005d399f0726077b7fe28c5034029fe1f05b25eb5a1b87ca0e960d6f5846bbea7908727" },
                { "nn-NO", "e856eb0de2f340401d7d273620a87553493534d2956515be00a815d3fe0a567db6e8720c2e64f09c64da3c53f58c28c99b3b981d86668d5f63e2cf3e155753c5" },
                { "pa-IN", "45f4c2a4cb2245dda02f987f5521180ff4033fa87378e604bc4f2bb89ce92b171013955475360e46a57ff054fa0d91206e3c68f664b100e2e86bcffc2c65ec17" },
                { "pl", "3ee6ab315b287fdbfb74e634bb8bee464698dc1cc263c762c92115f42da1d2eb04c9b17bc6a6a781950f6fbbd5cd826c4961032d041ee1c6705005b4882d7bd8" },
                { "pt-BR", "dcb6511a1d8a69d7eaea9028b55c2d4e7daeb5396b038aa9d83e67884dd7ac90bb0d5d0f1b4dd60161aae9b1f8334abde30a171c0679781e551b23ddb185b4da" },
                { "pt-PT", "49c8a9df6b94a2c5a33b610adcfbdd04cef2ef5f418b5bf872daeae5a12fd7201abe4af17ac7b2463e468d01b849f7b41b73af1f0b0025d257b8af443781efba" },
                { "rm", "19fc272c9083bcc59ebe9992104da2b5d63c33a1e30a0ff22d9e85d65903781760f1953692cddbea5da3374515896615dd95a830842430710cd8e8e3f2aaae95" },
                { "ro", "701a4413683c7dcf3fa79a95bb53e9c6af99c180d7bb79e01d427aded9a619ab87c90e8743354616bb40c4b635dcb77e685d3d6fad6a8c98455643488ce61c32" },
                { "ru", "f3edcf1668283f5d3446e35e9a41b9af1f3b931185e809b886fd6f741ca81c75664d7c89c575122ee92ab32c12f9765188778a98ddd08d1f9866c2da45a3dc5f" },
                { "sk", "d410e2e0c4fe6bbadfa286f20e9b6db46ba4260d80471a80316dc3b678f954e4ad7b57976c2c61cc74292c91c1334294f779d06f17d724ab13249bd30d11d46d" },
                { "sl", "6f14c9ab54cec2f24f14338830d005e37931ef3f3f09c00fe89927a7a3dab71e8741e2704b59a5243fece5cf6d155485a0c9d4db18018e16d713dd583ef0f922" },
                { "sq", "9665f1d4dbde7a000446cbd066f94da554557bcf143b85ea8389adf3bfa6a0fc60d5777c2fc9613e58df77f8e666f2e6bfb019648553daa80396931988a6920c" },
                { "sr", "52be02a32704a81c05e31585371fb7da691ecfbea09dd002e4ce8663e623cdc7e5f60021ff953eac73f0f412b0ff4a2f0bcf214801234e45ab7708a93311a178" },
                { "sv-SE", "870864d1f0200219e3577dd14a7d395ffb032b5f2abe966ae17986d95fac8ca622292a803cb56de6005b889013bf2d67252dc8cd84aaf4c680701fff2db70503" },
                { "th", "c6748265fce69d6045657d92f62e31144c9b8d7684f9bc5c13303697f08a00db7d08c15f486ba710ed72281dcfb0745de0424d87e2c9a7a5132d609bf42b8f31" },
                { "tr", "58554ef8920a21169394b4c7ab6beb6c00167db23a393d566615e9289df4ec569281202f7fb8f4f063684dcc46317e106ed56699adaf897e2df33be3d36c2d16" },
                { "uk", "7f0b1ff87bf332a9327543ad09dcb6eb159fad960a3028532945b80d8934172c97b642f1a0e58d3cf5f6904bc4d1dc92dc1f5bcbb0354487058c9fa5d2119ae3" },
                { "uz", "3593d7767914ff2743f2febf1a0b284f4c25562f26d122e90facc35d1a2fc1737cb324f751aea12b8b1b1f0d21b612ea1040b9e811ae5f9237fb2be2060c7317" },
                { "vi", "3b90314eaca770a4ae18959403ddf170c9ee4b0c9cc803bef201920e4e5dc986a2e471c36acf11730ebf13f3e068b5758b6bb7d8e967b9f9ed1751980c90cfa2" },
                { "zh-CN", "6b0a362829a06caba78ba314f16a67fb74a78e6a3011401a7ae581f0b6c6126f4760696a2afd0c670585fca038f412631ef5186d9968a0a9807f66afbada1428" },
                { "zh-TW", "6ff0ec8f8a90bae2fa4726af8020172aefdec2b38283467d65ecc23c53cfc9e414363eb83a36a082e0840f3f27a2ac5112f72a6bf26e6bce67a68d3184c78729" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.4.3/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "34c8a7a3cff990b1f691b117768cb75e3319328b03a3fdb7726d8e9f9913fb70b875583361f31e02c2fb95983d3928d7737854623d485edcfba6b7f5eff26a48" },
                { "ar", "d63bdd42f1fe318036d01bd869dd6671d23cca993ae1af1245f4d75284c9992658fc66c86a29f91e11180f8cf89b72f8556e235d2a270067cd734cfbf8291f13" },
                { "ast", "e2a9c4bf7cd425f55af326207e1841293ff3d4c1ff3cd7dc238087caeb1e3f107d8eaae5a199a32a32099d88e6cd84304f8abbe2c9a655d48879a3f604812f07" },
                { "be", "919df0d95088556ded54458ce3a918ea6670f8fbfc35f1bf2c3b49ad1d22450eb1693fbde73fe60f538e69e8bd859eef5f595ce3397ee8e0984e2276043407d0" },
                { "bg", "cdd3fcba5972413b1500c38e9ee0da52c11272cb0b0ed832bb7d1108f93fcf756d2aa3d6fef3ebca9e8e065af4a8619fc24dc3cbfe2056018ee65d827a691f7f" },
                { "br", "bdcf227f0b4810593e32df50ae3b1d413ad19a1d8fff2bbe8cd5bcebebb46471f8e5f070eb9ef303c82b9204fee2fa49e1cd618a4f0a9b1bf535e7f3d5271bbf" },
                { "ca", "094531ad287c74af9c53361b64d92b9c4e89139b5cca93708e4813ec39e936fc4714f29ab4c85449cfe6499ea819c9fe8ffb8bde8c18b080e47f9308553ddc99" },
                { "cak", "49a64ab5c317030d1e2b18a86116c449d19890a089f1a9d22de23863ef6f12ebd5957c80c541104f4709dcd58302074093346f3f71d9ec6e121e7d3099a96632" },
                { "cs", "2a54324eb14ff73ea3fbacb4d136a9daaa4decef49a24f61cb487fdaef81470007a3cf4269f3ddda0ed93a3ac7b744d3a6c81eda5027af225de31793bcd40b3c" },
                { "cy", "4331fb0d32c17efdff03d817280d8815bd61783ac9f73f3013102b4ecb862ab361031042b3b136e6985d2ca9154b1d40701869bd21112de9fd666b05a7010ba0" },
                { "da", "c0d43b28bfe1d907032c75aabf9de435073525790ff0968a09a7916e89455cc08c9613f498255b8c11989d552e66d4c57249e39c4d2db839129f13578d06c16a" },
                { "de", "47ea7c42817206268fa697c9df23fd3498b79920e3bc68d33f45d921b6831be9662b6cdcbbc0b2c8a24310ce10d3fc04403ad17fb790fb49e7d6dfdca238edf8" },
                { "dsb", "96d1214a109a71fcc29acbb1cb39a20eac415ea784e8db6c351ec583346d5ce05622dc5a2077ecd882c3c48d8c70c0eb607047bfbf023cc157d6ce096bfa4749" },
                { "el", "5bfa4768d96a4403f6b0bfd0bbff64bc8675a5329ff08fb1eda1491c40a50bb624ddc03d15188ae67ce7cf8d0634d2c8fb1a0eb9545fbad70f35eea323bb7135" },
                { "en-CA", "822bfc8c4325944cdce90370d692963ebea1ae45c301eeb06753f1687eecdd04a26634efd7d10d38604ed3aa73866e8e7ba4809f706af9df5a1abe6966b57488" },
                { "en-GB", "1f0b0722d1b7f5945b2de12b792307cf07cc1ddb854c48c6ba6bc841206e5d1b52b0d6012fe79ae98903d05c5562629fdf1eaba899e60ef128441e32f6a9a3e4" },
                { "en-US", "0e7784863d383850c1a17b340fa01011ebb14cbabb20b7528a1947769e0828c7a707d3ca615560de9bad91107aa82af09a19ccfd9a96f8454be05d3700bd0c20" },
                { "es-AR", "54948827fad66a8c4c022b8f53a7f61f667e1e6cc3026f4bf6724aba3e274f88b261b73395221de0b76d90ec95c741597246cff4942d16fad31c36b80738639d" },
                { "es-ES", "dbe8556c1423ea7be5dfa55f267ab0cfed97eb266782e336554387fc1b162d81b9e9cf173d866d622f1872e67e74de69c0e5cf8fa6106c1f406383f7d19c30d2" },
                { "es-MX", "0f2f468fd40d2032a05b83fb037a5252ee61d7c3a6b1318af4d0770dfe238447c7ea5a8cbc5ac2dd0406671890bb13671cb24f9e4671dd3aa5f500a6db63c26e" },
                { "et", "8126dc112f16f9c6df0e4d5e31e09db1817658aa405a83180f07058d03aca73c2f877eeed44bc483c8f028103e484ae276387ce6cc0aac015982e7baf53381f4" },
                { "eu", "a0764327394a70e773cf4a39122ab939fa44ec254dbd57ccbd04eae72d22512d97d2d28851a87ce12ae867fc2b3522fcc63a1ef158587302a1e577fdcef3fe57" },
                { "fi", "e5f05daea2b00f5a272d51ffc01f140979fea2f580761690cf38f6e9a6f20b7526191b19f1b7a6499602c4ad3e9c64d8755fdcd5bcb1cb5c9a53cb394d11e7dc" },
                { "fr", "49460221f0a612e0c0c21fade3673137e4baff5c2c05d4a9d43f83b29e83fe15c4281abe172c2fbfd6098986f03e5fa5593ab6edc49d8a9951054ea4f98143eb" },
                { "fy-NL", "a9e929be0060b93d9e85935f0a81d1eecaef8630417d3fc71fd58e10a3f39345425d2cb79264bf8d66e24bcb94c5874a1288b31f76a35f063b2477b3a1d3b1cc" },
                { "ga-IE", "5ad76485b0e2ece1102b83f965fc8b1dd8b93ddeb22616c2dffde94c9465f7e693f54c7f4fb1fcdd785ae0423deaac92c84a6e224f6530360c9c01f2ffc4eb28" },
                { "gd", "c7701ba3f9cf1aaacfb1c86647d9d0524fcd92604d1bb591524a02cd9a49d3bbc72ce92f9d09da0a01a5c43462791875ad6eb462b19ba3de6ad98d52849bdbae" },
                { "gl", "18d8a6e5494f673f347920cf5ac9435ac0c4f7a07a9dcba9c42ba9880a1da6cd09de54919140d288be64173997cb1e693b5abeda1292f6966303be07e6379156" },
                { "he", "e49d4ffc455f1e77bb4db11625df33412533bd56f39d2ef6f428c386c690c4df2113c7058653b60c7b2fd3f4f04f4550c259dfd4a00d448666eec91b26b9264b" },
                { "hr", "9403499840f3d7119e45f34b50712254372081d9a78d90cd067975b2661a7a2263a07e7e84f0222ecd3945220945bd600847a122a4a282ca2eb08e2310df0da1" },
                { "hsb", "1f6fa5ee31d8bd7af3a1b4b1733d8fb063b4e7a89c48d0798b6eeda105ef1438fcf6e34b243cfb328657ba9968fb50fc0c8806137aa503434cd276c7aea8f0f4" },
                { "hu", "e556b561ddac4a71892e4bb9f8555ededf1360358904e1c16bd90761dda873f95c271a757e29ee62c94f981a217bd884f5e51dc188aec41cd37049d9901cbde3" },
                { "hy-AM", "301adda832a996eff822fa9276bd286fedf9538dfe4c13128f3c9592eb7e714e666299258cf23a1f3bbda1487f797138e32f559af62f70dbfb5a4f1ce10f603e" },
                { "id", "5a215139611611f1ce761293b65bebd0ceaee05937a804d212e77b9e337f836a1b0a98765be130c1a315688a63338cfea3d55aa723ad5756b84f4af4214f1d2f" },
                { "is", "28e691b1b7cee7e90dd4c97df312128b980be82fa8a7f0861c115c4d29f6165528bcbbe0d3bc1f0ea854dc50d91f0d64dbe4af25b77b9fc9fb9be76825c8c3be" },
                { "it", "78e743771b508ee4354b7de33a3e815ed780e6748be28dd38bf5bb562ccef4de3d53603830891322b917e4a8423bcec4a8c097f730a5dcd074a999a11912fd98" },
                { "ja", "332e1bdeeeb5d3e62d53e524cdb19f12515af0f80663c775be64e7b455fcf3d34ace9de02f41f87c7c91010f70c46afbd14fdc8084aaad4adaed7b88c2ec7616" },
                { "ka", "ab17d54f434a6aacf0e44c1a555a3eeb35c137720ee93c6d3c3eb9870e5310b106ee8ea30b4bd38bc965a3b68a9497ba995c590fe7613d60eb662f2aab1c9854" },
                { "kab", "3bbd0f6b99d89c8df38d6031c105d1882ba789334cc910b38c131c5a6d4f2d716fdef1a7910622b64e2835e96ba01ea3b0649485b5cd17e2a2ab83e4c611bea9" },
                { "kk", "345c9f2bb5f6c781d7d8beede0771dd1888d36aa406b96eecb61da0315c8b7e7f6121afc54a0df62d04363a81211a5a5fa71b856e5b90be7d6ec0ecd06b1d0c8" },
                { "ko", "9403a275c35f5340892d373b48175b36aa9fb3498483bf6a2e474c3d1e8a8c67414bc10e441bb930ada5db1a31678e06537c85ba4ac3ad5b558c1d23e07d9176" },
                { "lt", "ad9f611be521966080f74f15a14e62c5c52b3ee712281b36829dd96d4ea9da06c61a3c154ddd50943d0c609cd6a7bcf6cb77c65021c7f92b67d3e34af21e6051" },
                { "lv", "2a91f14d5935b0d6fe7967856da255b45a17cd3ab9da213459c80c16c78b7634ef80a467b102f989a8f828a17864b30b4acd6fa64c86e8167680c940e9054136" },
                { "ms", "a8da1bd6fc117303ddd40f10b4245ab23f3628f259bd6f8bda41f249154fb367751f1688f148225d707e63e927cc4c8b8cfc06c0e8e5adcaf9a0d3ce54460bc9" },
                { "nb-NO", "0a8c7efcdd142205dc6c84bc4d8716104d65db803878e51c75d3629c9c54288dbf8710eb062dd7350a9308f924bff754a937b52d935579f62c3a74969004e291" },
                { "nl", "931b02ace25b279923648f0a774eda1bd6c7f1446fa58e676f153124dbe1a2ea5cc4d428a075fdbb7807fabc31e44a34e5ce2e0a539e61b0d2cca806365f5350" },
                { "nn-NO", "1f8cd060d62aae9fe6024b117fd10c9ab2ba1c6f1050ca69557a207cf687eeef1d185ec1d3d703bc2870715fa3a82a0391fc77fe2d931d2306bd407e0d5e851c" },
                { "pa-IN", "2ec11b76e3b3474aa5e4fb40150db6db08aaa3468073aef082ea4c5929b15a8b4124353b50bc394c586cd0e9599b6ae3f903d1b3d9b2e27b8c4ca6b0b5fa8de0" },
                { "pl", "30fdb6565e8abb4e53e769c28cd01ed8ef23892b77f136881ed5564fefd794fadc4e290410d0411f584e5a66cf8cfc3b786f75d34b996b52903ddd73adfc18e3" },
                { "pt-BR", "ab86427883cd1c829573423d1c85a9a57f034dfa5a2a7981444244d9d1ed8c567c7f19678eb50d36c1b4d232a1994eaa68d9cb14e01f1e9a8c4d34fb10dd3c4d" },
                { "pt-PT", "644735b8ebf56ccba7b541f860239dc6a5a16257c286d3cc641f59399100fd1bb6f907ee4a6c530d5a3e90772696f1c562cb04447dbf11a0f9f6c5dac16a0dd2" },
                { "rm", "39bc1041e636a7545a3db4875eca8eff94589760fe25f70c7a7fd8b221fef60dbb659917afbc881f54ce5f5fffec4685b414261bc4c3a8dd594bb06124c65ec6" },
                { "ro", "11fc00469b2b9d0fb8cbe9cc4a0a2ac56a9bb36b003c056d79e969a2e5e653fb3643400ca16da35675ec30e9399c62161aed63edbb6be2d75b783faf5ca9d552" },
                { "ru", "aa84ea4154d0aaf3480141cf9e842e8129fbadf94b871c017754c6411ceb820e9e52425e17140af970bac1abd1b4662109ed4a66cd6c0cd625078a0e4213676b" },
                { "sk", "4e1ca730614c5f60176649f373b29455dabb2080e055ed81b7e03d8fb85105d12cae08f5c8165b5d18a10699cf72b53120f45338f0dda14594a4a7cf287ecd50" },
                { "sl", "0c7b3d6328524e447087e3f406b41020c0d9b6e2d001aed0e2f9fb57673c10ddb913718a7cf18b9c607f5e691de30d9a8c6d2179f5bf861e2eb114294647f652" },
                { "sq", "6280e7ffa5129fcc34205c4c1a1299d47da9f46304c782ee480af797547aceb8feed183e68a7497fed644075956dd2c907563406b0e61b8c031854d07cd49971" },
                { "sr", "6af9d6288670d193e26c2981820a68424d4df6916705d6847dab0e346f38f9526587a1a882388d905422cc3265e65caf9f7b3b202cb71926d14ee71e28555d57" },
                { "sv-SE", "de78e3fdf227a393e622499ee0ec23c48a5cb370cb0708f58943ddb07f631fabe66cae5199190926f8574e55e5d83dd4856dd0ed820a3b7ff6959ec6905f0fa5" },
                { "th", "b74a79d0b53acd095ee2c31137ca2b80f7ae1d48425c395c6b9f501cbda291096eec9539085b21d8adb3c9fc3848c21f3b4d84dd5b9875114d3ce418c58f2dc3" },
                { "tr", "fd4d412510e96f9dc7e0c5bd16e1e5b3d0b31b05b2bf0be714c93083940bd007b23c8276c3b970c95f3b5b749878a02e92ef651673a822a742d17aaeda6d8cd5" },
                { "uk", "4f6f1deb5f85fef3f820656cd79f8cc3a3bf0bf54c9a6e50d9d89c247ae7b71bde8470a8591743793e0cba07872c4ea80e4cc83930c3291456fcf5815691cf20" },
                { "uz", "fef8c74b68c96cac8308ec8d2e708868a3599fdf86b5f45f5c02a4c76793c246e3708b6511d66a50527bdf16d6a6b7243431cc4863f1b215704c84a35b35a8ae" },
                { "vi", "eaf0514d7383506d2bf85768282506cf4dc5709744ef0bbcb37afab8831db5369856803eb40e5fee510bf7a0145f857745983e4b1dd2afeb75f934284e45b9b2" },
                { "zh-CN", "785e3c72732faee8e6ad32a7341b0ef135b4a20da2dfd3d9785784397978135acb7d3b953106d3f43743eb09d12f41125ce34eabdb259a37c8c6a8cb33f73627" },
                { "zh-TW", "32a9b8d4bf5dc802ce795a789d6b8db0393f5a13a2821655fc127b1ff9e16eae4c5b78f4b966101f6fa23da48ecbbc8b2cff8078f01d4e934dbb239a557941b1" }
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
            const string version = "115.4.3";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
