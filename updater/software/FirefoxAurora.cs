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
        private const string currentVersion = "132.0b9";


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "42a606de2b475a6b89fafc7b5d8bb47abc64343bced1786903bb7bf7bd1af0b25aac0b290620318987bcab2ac7bfbe941bb5f0a5c9d0af2999e0b2423e9a7dca" },
                { "af", "00d1976b5e492be7c2bc3afa4c09297603c04cf9588190e580abfe82cefe6d3142f9673d718790cde3793f286167fe92dd012fd19689ce4b3a500a32cd89b11f" },
                { "an", "5cf055b033037a3be3a629d029592a9a8b631b8c8fd1c4baa25393ee4e1c248aa128075baab06e44b22f04a4058e8ede8491230352198d6f83d4136d3e944907" },
                { "ar", "29a6e6c35b712579acb21326fc6d31ff0690a8622ceba01bcce22ee25e9199bcc49b078a62e0e0f86d780f531d82d68324c6a158c0c966c1c7c9bf90cf2adc5b" },
                { "ast", "d0619015a6c2d6137801c57572f581193e4b1952998266540418440028fad15f3f9d37c5e458faeba8e1359ce229a8eee4eab126dc6aa8c3c65ea8edeec3aed8" },
                { "az", "205476054e5c1d8b2259e647c07674bcf126b42c7e0d303dcfe737d0fb04dee57382bf00b94acdb49b310fdee85831ffaf9d485e95e251b3aa33711290964e31" },
                { "be", "fc51d99af58ffea48021bb1440591a876fcdd63370c2de0d8404729f4f6a64cfc0071af0c8e89db1d21562d486aa9979954627a511eb36f5a0633cf0cf9c9637" },
                { "bg", "9be7ce762245934de880697d7553fdfa8bce05747c9be8496a1cd91d6487f98d721ef535af52f01657f81a76c27ee237d972e752fe6d092228d5b354d71218b3" },
                { "bn", "ce8c7d459ab18f9b3aa440ecb61be5b2937af74395c486c7576267b4d49ed60e76ff20f74262ce0cb3b8dc831501ebca827b382a68963b761df1d7896196ab2e" },
                { "br", "075a0c561981d7cef7e07ea9064e045feaa1aae9bbff203dafbfd0bbc50cc61190cfa80bb037075d438f1d578436fdaa0a7a57cf3bb7bd9db6d7596a94afebbf" },
                { "bs", "91d235ae226977b775ca24e8f64e2b671c000761c6f8a7eff18875b21e80a60d8e9516310e8daf6e325ecbdee263cc8aed676e909d9278567336faa3608f25fe" },
                { "ca", "fc3a91ddb7faaa484aed481b3319449109f893f3f220981815cae2109c7f6d30a378e43321eb07cc2d23c889b4320183f7c40e7fb9648a02e32888cd85fad0d9" },
                { "cak", "652255fd472a45c1db3158c452d42c1eed734337ecfefe9142df7e34a8d3a27dc61331fd881f599cabe45bda689f9633ccbfb80a22734270030845525af9c075" },
                { "cs", "68ab79178bffaab20e527a9d141ae47f05d5d145e695b5ef7cb29f70b347f61fe543a2d6dc2e48657a3787d61551bc4fa18beddb68120513b0ee3c94eb76e2d6" },
                { "cy", "18a2dae62e71585b2195a108997d6312276900dc707ba5f8dd312a124ef0b598c2dba5a7a9913833f033fc9e16a53f142ded889f3a4bac4e0488113599b8e3cf" },
                { "da", "bbde258632654b84c2254de61c18d07db729d89150f8b10212a4bfc47b03fe959531effe705017074840baa4557a969263b7c3151c6ddc421279049bc7a52ef8" },
                { "de", "0b1c1f1930ed69a76de8335b18b5fbf53223ea4046c107c2321725d2b32b1b67df306bd85b6273af6cf8fb1f642cdcb52380c63d29f92c614de9697482e5021b" },
                { "dsb", "ced0ecfd885d0c47cb91f6dd13425153ad4975d29c2e4add3f00021700d0f34d054dcb2592a99b349c313b7d7c06e3b76fb2cad22ce766c899d484a33bbd5240" },
                { "el", "3104074b6fd4e1e0630283514ae9b39851c11d2fa6f71089900fa5356326e98277a84619cf2d069bb3fbb0e4305ef9ceef3e820a33747c0fecec46c00da2e0ff" },
                { "en-CA", "b45aa306d82f81ce0ed3df358447e09afcf6ea8ce44dce800dfc6b4fb119b709f1c836fac986ce6505034984f3c62db752b55adc89c7468a1722a4a67f5b15f7" },
                { "en-GB", "db4a5da40756ebdc5f108f6639967f5ba4287befbb4cdb5929e28c22272465d0f5a58bece6544910a552cea1d191d6969340bebfc619e04997272fb925440455" },
                { "en-US", "26ed72f3df8e261e0506793030051fa07f73e12b01a9c26860a412fd8876368dc3cc1f05d009e99b9e5599cc27a112df5f9d155ab906bc77f326bce64bb0df1b" },
                { "eo", "7d2d025b7bcdbacf8d55c91f74b10c049166e4a6392073e81dfb73e4d50f634e8b9f2ca0608ce2db026a4f9334300f0616ccf592cb4dcba519ff121c847e7ba5" },
                { "es-AR", "2fc87b44399801e509ae83415f23df6bd0029d2e5be7dfce9509d9e268f197b25b81276121617c5e6ef6e877c767ed46afb343a34dc22f0d4e0428cbd31af5af" },
                { "es-CL", "4adc200c20b06c15115c6776f6140550394bf7f04641a33f8ff69c387bf71674a450a031e38f6b71a32716f47fb52e10a6e14b4e27c924b208a9b3b4c34da532" },
                { "es-ES", "8b32376776b0e3035d24f65f2c9f6abe69f3239d1e0c506ed2bd4c7c86eef898d2da7576960e2db57e4e040f41c25489da0cd2551aa769c3b699f4ed7ad39073" },
                { "es-MX", "ae55a5d2c6427184c24022eaf449d54ae0eb22e6d329f3b0892fb3d1712f29b4824b4f31ed0a57484147b45d1152aff6ec6bbd431d818fd632b670ed0ef6507d" },
                { "et", "96d8d0ef4234442613b0cf9422a0c036b4140455f9f1a777a17a7781abb8a8ead58c31b7d7b279fc1a92ad078290c51a3d4af0496926656d9ddd70f704186160" },
                { "eu", "350be42290c70c507c8137c9610d149fbb8094bd7a548d9777d535b4da71a375193ca4ae03f1576c60c2010ced9e48718bd19aeae09251b6109b14c5b663a7f1" },
                { "fa", "dbf40bed8daa1e7cf5e7c956caa5bdfcc17585d5705abd59769c08bf93576c6ff47d8e373dc615d3728a0b955c40efac72f9c6917ead6d145cd18f405a676dff" },
                { "ff", "f933e9a5c45bd008f12739c1d0ae0fb932f2e69e006e8fa9f82372264184a829e626177313ea3feb9f09691284986e92b07863619f4ff21a903476ff8e370901" },
                { "fi", "7e9bd639fb528f6cc416df31f9bebaef7f59d62e4849c6c939ad4b899b8653eb6eb534891de801a789829b0fa0d6b9bde87eae85e4ee553f0352f899a9efb504" },
                { "fr", "fc365fbdc48e0ab62587b2fffa11aff42316e4956407a231e66a62c1acb431241ed227771dca0786418974fa11fda578fb0170fda780958004e10b42ba0fa3d5" },
                { "fur", "d805806c5f43ab58a9866d9f6fc3cfc1ecde071450539912412ddc2decfeea36c30119ab37de5ee3812b0b0ed2c8fe6c78d15fb1f0acabd5dfdab5f35a168821" },
                { "fy-NL", "6dbde5ce6ab452436c91d13a55144a18ee17360400ed89656802ace98591fcc6458a68045d35266b446d2d142505cc992b146a7e74a0c21afc07a753a5891577" },
                { "ga-IE", "2d2c701ec80954df93dfc5a0deaa119ab17ba29b190552331ac6ac9a8b9cab84213c7625986f4dc45db9f38d4479c6cbf54eca841633b9b852c746eb763e447c" },
                { "gd", "774c50b8f4d3557c3983efaaa481cdc9ad6b61a517c02c6ca71b51ec5bed53d65e0a8b782062b3944650e1f0ee34116d1eeffb4d8754d69f89ffc27b9dc3c569" },
                { "gl", "999a990c46459bfa376de8fd97da7446b667fc5621e45aab7742dd2c5b502a1bf1b65321ec0c7571dd7f8f81e9366dad0db5f2e481c7036342b78cc4911456fb" },
                { "gn", "b239942a5a682efc60d5aafd05cee2a68b22ff1169f0aa328cd8bc872ea1d028f0cfc56cccbcdfde705ec296da5c8e9e1321cd2695de5ff31e1ae280158a3814" },
                { "gu-IN", "51575bc8369b72d6b3824df6de7a94b20b3f6eb665d594723f705a3bfb5ac5258ed1b9c8743d5c11d4b0bf1e0655d0a75eea25db6efa6263eac572801afb4336" },
                { "he", "c8084adb948f4c3fff4ca4413a697dc1ca6d20620f6a20a36e1d3ed102228ab6269f6432a76e6d1c9d7fa0432652f39b8112c6f45f1c60d42c9ac719a0945198" },
                { "hi-IN", "5f8a92c596bf5fc6dcf53b66fd69b8d9d1edc0f005f57f0ce5a2d2a335d703a350d46575f48df3e5b017408d4b80fda10e37cb31bc94bc931545a2ad727ebb2b" },
                { "hr", "8e82dd4edca7f475e015348a1197a88ab7c8200db13af2a22c4272cdd0a6857cab985d2452b718b6fe50c04b27055429b0afa90af80a06afc22d9ff7c41e373a" },
                { "hsb", "4f9e82afb94773d23e8c13e17aac7d2265b28d1b6b7a954f84c4ae3abf4ebab280b5bf2f12cb9eb25c7c620d21c355897fc0bdae5617579ab87ca4972b606039" },
                { "hu", "ae187803148b932b7c4071ac8a1b56c4e500be34085ca3c662838d614b741c902b4e5e6d7f4b9029043c6cdf2e0befa5e22853a2cf739724a63e66d6a1a66861" },
                { "hy-AM", "a4782a929e1aa20a8787cccfd5a8796b47aa38d9bac09168608d80a78e4ced1b800413a22b88ba6cdfdbdf68a71047c2c37b79fdf3736fb70ea6e96cf75500b0" },
                { "ia", "fd7f27b267c577aa1859501deb2e92ae86ccf98386161ef08d647764e7f11bee1772b0870d79c1f3550c580aa943880726244b86fa660ad435081724132f95d0" },
                { "id", "5bb1fe6435c394450928cd7d1f22419ae0bf58fdf064379757f1930668e9f5873a4d1d0ffa857b92f75d112b42b5fa070856f31f4c0541751c4c8bc4e957e649" },
                { "is", "ab71ab0b9bc86f1e7df807646d943029e2df30c1aae2d74705931b6faba2d1a18c1b082b6e8b3961f68bc50c036d29b6a5ec3b9d0f705f78e249ca94e1ff866c" },
                { "it", "04f6f067ec1500f29df16ae628ba5006c308cc88e5abe1b5ac6ee2787f5be0131ce62338e8714cfd713b34c7187d727906689c5fa06cd66f8e9b441e74c3345c" },
                { "ja", "39c4c72476c923f4e2e87b6f805f97a87e2437fdc5afcca4eb811af3d947e02fad7e413ea25736107190820298f99f185e4cb24ae88d14aa8dd4898bdfdf34fd" },
                { "ka", "b870c44737b94ae6cf8ec860ebd6785bff440f243ace06709bfed0b553ec23261adf19f07136d7af73fded1acad2552f961f036614ed6e526053ff65a4499e8b" },
                { "kab", "6db4390fe32c02acae1d7828897ae8f569ec31e80e1cf8bb211229bf5c58bdfb85ed471d0b2ddb696042b406d25598a5f1e2c6cd6e2a15cfc5d251da9a69284f" },
                { "kk", "d6a419c9aed0034bfed89a7372138b72b70c8693bd6eb773069d02ed5c719fd0cd0a26e165555cb720a93c5db62dbb823b3d5a78168871286eac653a80221fd1" },
                { "km", "e62ef83f6450bdf10b75fe10308cd9271ece1d6dc568618c869fe093a4bbe42eb78138dce65c6273149d6debd9938d107dbba79370ffcb65802da85fb65c99ed" },
                { "kn", "842d28c0b66649e70ae9b35e962d88d426227fc3be22b25c2b2e1e76cf6ebc58b6c04e446d67e20ea6229978a6a0a0088879efdb8643a5fe220803372fe7ee88" },
                { "ko", "33d8e7e059b1924f3cbae07a789cad7c021201750d1ac7c5b5ccc97871efe82df5065c7dadba305ccfdf64f53ef658139712520c5c724ef8e2191319b66466d2" },
                { "lij", "8cca347873370ac1c9c4adc9aa3de9bd7c45ee4ec1c04572e81ca3ef1e17ddcd551647f00579043be7270d5be5a69c31e5b983e1764bce4a8feae5eebaf72452" },
                { "lt", "0de7acb18aa798df7784e6a67ca3726aefc09e792891bd624f9c14a5bf094e19257633ecfa52caed90a80338f9315a95128d8ac51b433a0596b53d5d0aabb68e" },
                { "lv", "be5f19894ce898cac5568fe7181da8c410df25ee516827402a78ca5f3bba2099cf9c605ad69da745295b509f215140d791702da630ef2e66bad2eefde7a53f2a" },
                { "mk", "cef28bc7e29baeb56114b14c5f6c65914fb9ccaeb802e4c07e71873545dfc73aa156c5bfc5183540e34a04a32b7bb8a0d369a328102873c8ef618e6507da2fd0" },
                { "mr", "5488ddda5ce8d72df2cc376cc103610b2203c1fb6a2eae9ce322154adc830b535b21ba8e661fcb4f45a48dfc3084a115872121c566439edd3f829d518ab7349c" },
                { "ms", "264154d15cb7f8c68c2025de634b3ea89ffd5f9625665ffac05f70ba7977fec8b1274606a0c16de27a5ce0d123069b54bea2d33ba8aa7b1aface6d6237e44f34" },
                { "my", "bf6a99f2b30b57fa09e0e9ece9c62eaf26c9d77b44ebadfcd87c603d2ee4c605854e2390e38935a81c2dc41987844f818640d7f9ccb89476c04716ea68f8aeb1" },
                { "nb-NO", "c5bc5523bd6246ef639f3c8d8ed162fa6de52bed49270c8e56ea7602ed80d741254f8f62e3dc5c300deb115cd8e8ee7da8f9f642226754b1929052f0cb74ec50" },
                { "ne-NP", "1f6a529106c505fbe72d18d13130bd575724d9421d76fd4a6ece6cb3ee4f333fc3d7f76d5ae97d4acce181b0608f0e96c9977f4da0b2ee493148d78997a43527" },
                { "nl", "fd03a99eb7107f27c0a07fb4d3f653a6807064e36db21a0f7823c30538d819285b59cc3b74d928160e2774e68d5598494d28f458d910f22c8c9af782137a7fbc" },
                { "nn-NO", "c1b339fc0d3e312ebf4497c84e636b85ada94d1968c7215173a340059ab06aea88806dfe08274366a4d66a983f60cc7edfbf61fd0ee18c304face674d84de142" },
                { "oc", "9bfcaf2972b83603a6892d78c718499df8af1da58bc8e4523c7bb2a971ac03f5e51e669c313e0c7b195f9a3af9b20077bd95ca18ce16b6af75768af81a3c2c62" },
                { "pa-IN", "caab169d1bf461d3089a7a09734739c6396f956bed5ede6ec1d07ffc51c7e6c8ed9e784b2fa4e5fcb6e1ea7a82d2500c206c1f7f08b46a57966067b1ed0340f5" },
                { "pl", "0419be187c4d1de8e15ccc0f44c1e6fb0ec5499ec5e4e49ed06cf221fe8dc650aba6017380690d1c36b2b971a636572372dd506d13ded8f846b5dba4411d3f79" },
                { "pt-BR", "e009d9d0d0c3a5bc39716814611633b801de83bf91083d780cb6029bc2560476a2796c548d9ed5451cfa128b854899cc6e2b6b202f1fa708402267042549f2d4" },
                { "pt-PT", "98a1faee62b714fb0005557726fc1af25086331e9705473c9540edb736a9f65f1542703125d6600d2f88212726146522ee2103d1f9266ece031f4ea536de73f7" },
                { "rm", "6671ecd2f37948ba38ab32caeb50435da540647508420c896b68a836b98c1bd126a867153e86b308a25a2f7ec20a09f7ba851ac9730e40bf190f2f822c1b6591" },
                { "ro", "69c9d60a448842a9f17f00b9bd6e0e84a050601832667e13ddf189441a922dbfd30575895db37343dbba3dd8acd314b47879f0767b9b3f2108ce8cef5caa1a97" },
                { "ru", "85f56a5837ac0636f0fcf1ce9767374d9b261232164a51d52a7af44ba3a36d6e7e3ccd624c5c61de1de6ede2d7dd0d882cc942c68c6baa5380fdf5bec7ec3d03" },
                { "sat", "25ebec8d3578cd8da329ba4fcefd84165ebcc0add5cc8146ab8d97d471ef1d85a55bdb5b2d735ff8f22966ebb9323f453230ab2dfaeddf15e878ab2ad1019b60" },
                { "sc", "6ee3fd45d249bd121cb61cf55611402af67e556cc0f672b69fc11a7c64b8a9e3f458f8d639c969a51ade14923296117780c917268deaccf8ba940c82f187a36b" },
                { "sco", "702c3ba6f31007807ebc36640e86b473f188e042b8c63fcaadd9be2925ff6d8601f4142cc5ed0d2baed932b36ffb92dc0ab7d28cdc9af32a936eac4b18277541" },
                { "si", "f0f53f5829390d736dc100889470986f4b797a703f214c25ed9c5513b4e1ed69c37230b9ca0f362b595821348e77447c7847ede662f46ebbaeb15d372eb3be56" },
                { "sk", "f58aba2f493e89fbcc4e9b885b1401ed0cf90ae8f1718b6666be486613968c76dde1ee1795bf593548fa26ad13fd920137c18d7441b6dff8519594f6dc678c84" },
                { "skr", "6a1ee343b7f88250d96f3ee082ecf9a0612c56a80ea913d514af2e5e734246e035489c66ee3c64e8a9052ee83e687f459dc3d1ec432158d3b97e9ce7f8d1b095" },
                { "sl", "deb1e121891a57c766457783e3008675a597a3d0a1fdd1e46ecdcb229a0621a56a9bca98a55e9ac0f4aba9b26e9a233b887a0e7dd88594fb9f54f64b335b9057" },
                { "son", "c753bd13aaa15259500d55920843d3127f39554f9d2757bd5de96cd4a64cbeaa8bcfcbb32e5571a69d2af4ed88c0f056f23222f37d79e70c9ecbd0d6da268d11" },
                { "sq", "c42a1db8a1860c340d2823024780252bfbb661fbff2d01f6eb841edcbd6d131616b07f7a2d401dc88e514aa0c8a8c3448f4b5c4985f44f5e07246c5392392c26" },
                { "sr", "8565b417d207774921a4cc0e2bfeb24c3548ba654de02a680fc9d6c2ef3e8e1c212ceb36162f52a49bb6b64e16a78cdc9ac58b0b14d9051fa1dbe003b8261a29" },
                { "sv-SE", "a8d9208f48b40b501aa557254658f3788dbcdaa0b4066bf34ac47bdba7aa6350c8d2ce691a80d13b637f16e6dd629cbc7af2275f5ef0d1888e7f42a29393805f" },
                { "szl", "0580ccce16cd0904282760b5cd6b759b0a5b910b37a52cbb19f19dea96c99e60190f436c8e3e6ea9714d9b90a9a0e3e0362454bb262a791ba2f89bec504578f0" },
                { "ta", "3804530af32b42ca897e27215ca1b58287deb4de41b930cbe3ef7c7fac4c61f80b999a6c1eecb55a21ae596ee3338018d723dbcccb8c17117fabd47d242666c6" },
                { "te", "2aa8220ce94489688ff20f1903cffdb6e39faffa991ec814b9028bedd3e57dce89c2e9fa355fd75ed53f72caf2c917e3cc0bfd625b75cc8caf94b380595e7e5d" },
                { "tg", "221ef668a48fd8e51907c0c9f0b8987681ff28773319552f2b992ca57deaeaf83349e52f500c9b21631bc1e73b1a87adf3034273b8e9e807db57331db7e48a93" },
                { "th", "8e5e39fe3b4fd681e90d5933a46fa35bb8d745e1e0ba9ae40bb03ba286a7f3f94def38feece87ddbf483ae480a61149776d805fa4cfdd233ab2e1c546d4048d0" },
                { "tl", "25d8b5f627fa8eebd2ca2aebc97ec08057afdaf399733dea076005c03eb2a14e512f0e0f6771200a02ec2ca57cd73c4d6ff6e2b7255dbff96402b04e3c281801" },
                { "tr", "f0b3402ba8222237ec86fec3e86d811578562744cb7dc4d503d8f70dbd89b329f9384498e66f252c8e8195ddcb8a312c89f9838ccb947ca4a4aabde62ddfa685" },
                { "trs", "0101941f364d14576512f4b836ed883b4375a6a60eb4496e369b217ae07370bdb78ad486f6fd5d10797d91671f640aa3857a8b2608701e830ce1d13ba8a2bb12" },
                { "uk", "e2d2e7889f3cdba55cf39613b8c1eec650092cd13add528310cf3630935388cd441f38c7031aa31f49b397a6fe3055670b697811468d8a2084e89ad6bcea255a" },
                { "ur", "e84e92964570a3c2a4c2359927c704ed83fc4f1636763b4ccdff651616e0bfe08d506e085ceda57f02c5821931518a93748de06eb545041b89f4eeb8c1307d25" },
                { "uz", "3c589f44e6b19477bfec7740c68f9a3d479a65d12b80e09d0d5abf0cf88e7ac29c194ede5080b57a336e97e657788b4aeb4fda59ca388c5e32387958d0462d70" },
                { "vi", "c263340f95d30196d7ce383758fbe8cfb446e74fd12f2701781308670afdfc03ac01259bfeda562f3306cbc83d4a093fafb7dc3480ded2b8d0545501b3536726" },
                { "xh", "03be7c52dcfd68a5d13d14660bc5f77506abf1660f9f408546ce547c57f05cd81b9503c9fcf59fba125a285a1aa6956baf9f7b0dd6d76f04df0a195f1b3a8458" },
                { "zh-CN", "6b4aab4a43a676ca1e3c2f7b46aa1402450e048674a2b96711e97b6bfe4dae04d25795608c4fb93ddd28d4b7dcb66d0139d4fc172faff1d5d0bbdb6cfbe1e95e" },
                { "zh-TW", "6805945d34fde2f2f9c1958f68e0a930a445fb0d6a75520f22bad96c28d36e750fc4e955adac3aea56333c25c8d256a1b3d4b379384c9dd351d1428361ae3789" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7e0b45236decc428630a6ddcccb6568b16ca143591679c68693152f202519769648f7839a42b20635a5ab2805e67e7393df90081b7f6ec923a9dedeebd7fa073" },
                { "af", "e759f65ef7781b72673f07276e115c2d3497ae029e03f55750f4dfb955b3e536910fc040c35513345d1a37f3c1bd1f71785ce7e92e5339a3bd8da63f268216f9" },
                { "an", "af6ac7c44e1e29c63762f44a7d884035c5d9a8545bc0428c7c4914d6057305d4ed0233021ee9d33a781b76ab7edd12db2c53127635ea1206c64b5213f6a1d9a7" },
                { "ar", "b6dd30ec40c601b00c91633580a16b25656cb614c7328a0531059ddfd6dd1a2de765972ffeefb7028e4f12cba10677d9cdfe12b069e807f7b6c5d969adc77983" },
                { "ast", "084efc25899b78d9aa718b5013dae138db30b3e6e18ab6edc5410c991fe468ea8b71bb0969590aebaedc7f03c68e1a695341041b543fb0b7be6ffb26ba5eb6a6" },
                { "az", "0983f6370b278cbb297dc3a550bd0f0bb8ef60f77006a95b361630f0b8bc260d69b9eb7a1f8d0fa20854e8b449dc797d642434730e48d745ac409ad17f4d8353" },
                { "be", "78bdbfe1017a30efe0754a1e4b7749e982bead966af6a8468bf2b3a2c7114a184436331c167aa77267b5f1621e82eb88626a5019ae9cbc95d46070f74878539b" },
                { "bg", "5aa1c4680a3620ab2355c5f221925126a1f3afa412290624784dee59a6f2653ba43c467a981d7d19719cf785ec803df05a5080024245522a9fa8bf616cf0f4c5" },
                { "bn", "71d2961bd17740309224db487c31285f3ffb564d379f6285f80e8edcf1880ccd060d85cbffb4ae9d46bd8def0715e8fcddf7beb16a301caed8a4b1a2957598e7" },
                { "br", "e1e29e49123f3aa220db3fc8bcb9901d0fd21eedd4273cd01a976493c7ae420f21c27d5deb325deb104f7a829b17f1ad09066d21a2e29d1a92cb913f04c9d7b8" },
                { "bs", "183b012b11908017081367998d88707ea34af186c8c8f2a73ee043f29d14d4b89394cc246fb8ef175b7aa95c175112192d15370ecbb0495cc9b85d6f94d4acbd" },
                { "ca", "ab29ef77861f4ecc1aac2d582f3912261d1a1752a81a8ed92d7e090d6722dc344585196b3d0158cacf33444ec30c18e628ba2d0dbc13905956ca81e08b4d8950" },
                { "cak", "6e05f0d68a22594b738e5aa51c49eb76643b79d66719122fbfa2e06bd9c855ce51cf6d678adf86e054cf3fd52772035576af93aab1e582dcabd71809161b61f7" },
                { "cs", "6f6f305859396df270badbce33df9dbce47105ba30d421bab6fa2106451956ebc53d03b977702c18406a9415aae7121e82976168b39bf67c555e32c5304df9d6" },
                { "cy", "bf391ede1970d034c3a92094cfc87a3d0cd3ac3f32c76e07e13f162a077bdfec91d5ddbe5648fa03d1fe37dc141b118ce9961da72786d5aae3318236cedad1ae" },
                { "da", "85f63ee4c2993050627100fac61633fb0ecc88512e90a3320f8775d81bce971b197b72c8b32827c653f80578e6ccb8647de335f4b2b4c1884edf3e159743edab" },
                { "de", "a581608b792296da5df95a385e32e3f7e5e2f5e425a87410fc02ccb7ff8d8248bf94219e4e0f0f61f506c335d0d76793b8c1865d1d8449000add25989389c35f" },
                { "dsb", "560885e4b4174f8e7362d2c019d082722ba63d99659b9ff1b4677821321530f88af8b01ae3f14930e2b4dec562e8176d9cf8fcd0c24d96aef4a3530762dc1955" },
                { "el", "06b97c3aba6417eaf0ac91037b225ee6694b0755cdf9f8ef6b0a5085e2a7649db1ac4885d9a79ae5d480b0aad44d7f9e4e458e1d51925bdc1a0efdc41b90b3f1" },
                { "en-CA", "15a97e95a92459e796920b3fbccfdce912ff3e61d3f64a12c4f667e8081e8830b52927c2adc188928549009678990bfde37f85b28b06701a0366e656a601f0dc" },
                { "en-GB", "2e0ae5393be824439aa2d4619507d7ee001e47d80a0baeb7c98d276265f0991e57574691f480dd5fcd3fa9770791ecf682638997d754997cab5304e600efa4a7" },
                { "en-US", "d11b61946f0710aadf58fa1cc7055e296fd5b377a9f12095747a6dcf43c4a056427f6c0e130656d367db6aa81d691b109946917d61a256d295d1bc3710200d58" },
                { "eo", "7d8fbdcf6801a698be953125e7b8a51ff1016ae2968a55b436d9b4a657998a522a808eb1827e9f39e39847de99ce11f729413084e009b34922639508cb1d1859" },
                { "es-AR", "557e73031358f6f542091c81ff8e423baa35aaa00c6baf99b148484e311f73a604ffb2104cebeb7adb4ea8ec962539a1b205e39975c473a46659d247a8cc9f9f" },
                { "es-CL", "d66acd1f043f42527458a35c15401f16e22a6fe968f996d7f7ee62b8e6d9caf70af8f989d891bd06c531f060675c84ca021ca13e9a47fced04e753811c04ebf3" },
                { "es-ES", "28e3018aa5825b0ff1ecc8d1683ab2722569117f0d0a4d1f73ac4a63ecd3a2cdbed5630dc9aae5b8568c700ef2656a7971d5b6f9374d14278474310172435e50" },
                { "es-MX", "21f4394b408e8fb6dbf8fbe10cdb783f737f0a08ca7b1b0d91e9d0ecfa8260684a2c6b7c613b48e14b6cfd6ae4778ac02dede950641c9ce4f703da0f7670219d" },
                { "et", "2abc2d2b6d0efd94891b57c8b39eb5f1160844258cfee87b52f5bfccf68b4f2e55473af8c5d1d21d564c48769e84c683452c8153fe1ef184b57869be1ac3a3d2" },
                { "eu", "b21d8cb2d033ce861b61e784dde9b965e0864d5521ad67cfa8e1c9297f258cd0130fe8018a39d631047f07bdd401c43bbefb1845935f21caa698c8941335652f" },
                { "fa", "3c7dd133b3ff9e5ddb849e10e9a7af69181663eb66feeef20c0288465f01f18b438f0785b046aabff3804048aea3c239ac42be57ac7cc2ea69ce5cafd4dd3bd4" },
                { "ff", "8241eecf38bf110b96a9df9d050c4fc2b4728d41a889881e138e5274425c11bae49b2eedafdbb58879868703aaece41da67fb50d0889790451c210941f4874d8" },
                { "fi", "508385598a4c2996442fe8862274e6bfd0f478071c88f1df5b6a3a71140a39e2390f0fcbb5c7f07be501bfc7291e8c462adf4b773d7ff2805b420267e67bef9a" },
                { "fr", "e84135e16e0f3f74d41754dcdaa8131bbc40d04001cec0640e3208d2c5664294ca022ed1354b318300438776343915ec196c86587fbcf58692b4b054f49f908d" },
                { "fur", "9dd67b4598dcc6c7e34778b0449f622312eb6750195c28fa6b021af29e6121b41ba24e622a0acc892dac4268dbc75248a0044ccbb087604485fef5204478e0c3" },
                { "fy-NL", "aba8a40c663d3278bef05507fe229e2fab99485263acbe25588042e22f0c7aefef3445a7d353a103f5893e57986a79195b50c27d3db07083f87ffd37212e8243" },
                { "ga-IE", "3540b6049965b0f8f18255a18256bcf29328919237ebf841f449afd10e672b73e62530caef1050988de869996736af0bb07936d445418c446a6a998bc2a371d6" },
                { "gd", "791d0c0892ab6f9cb4824cd07d0d770d6354355443c3d40650aee82fc7c92db63acce0ba66e9bd3f0d2d0fcb9af161c2466787aa852befa3cb651016e2d8ce59" },
                { "gl", "bf7b0420aff2006e003b879c2b75b70bd0fc802191ef354615ce28f99b21a745bce9d73772e38a1f33f89f2306f57b1992727befd375f7baace848213fb50cae" },
                { "gn", "07c72cabbde06294cfbd58c93024276ecfda17c3f39c8fab3e982789952305fe50df4df83cf8fec6cc0d7fe36ea6aebc172e55ff57e3ab9ac611119d6b0e4a79" },
                { "gu-IN", "6b9e122aae9875de0a629f0284ab2cecade2b1613ae9415ef250c9a8548ee456ab40e6c14330d211fc7ff103aa98ad5de2eecb9039b466d7df68cb8a2460c120" },
                { "he", "35d59556f61a70492b2e50714b926d3f83c71a6cd32533535690d41d8b1a33af5e70fc4b5ba2f13eb7d44cec0f5bef91809271425b5464500bfc83d27db67935" },
                { "hi-IN", "66d9f8ded59556a6422439e13a4a0e22ff18a5f139212ab0c2e04524ce0499a3a9534436012bd9922ddfcb7f70a3ed58ffce99668900a003d26ec4ca2cc2e968" },
                { "hr", "4878d5cad7a44e780934ff33ac5c10eb74f1df2f580c5b4c3fe536c6b3caec20c7fdfe71b5f3bac17f90438477bef39ae141a6f39a750004ad1b352d9d0e74f5" },
                { "hsb", "a790a30e9854e03223478ba0bfa8ccedb140a8bbe8d2609fe42ea3aa06aa521a8f5b45594ca5dff752d0bfc6d5019823e24b65a1527b8f1a7053a6b594d90a74" },
                { "hu", "53d5e267c37413930b533ee5affcd874c66b0bd83f86e30a16c6068aa4a368ce596c246965e6bc7cb22373ea17150b70f2e86cb5c308ab36252848e170318a7e" },
                { "hy-AM", "099268355958e4ec452652cdd8b9b697515903bf1ee79612965a3081a630a39af4be15ec8c2b8e7188fdcb8abf9fbc66845cd966bd5268d1b054c1dcb967b2d7" },
                { "ia", "39eacd2bbbde5fe1e6d4f4c245851d34784443fd589cc35f4ecd68b4032d8e6ad1e9be63107a735671e679eaa37382764f5ef9fa825df54876717b08f3d2d556" },
                { "id", "cb92aaed7bf855c1a4f7e3b29ccb182976d92dd80f37d47739fe1d95358582d81b51849f4bce0f4daef16ff129a9b81d726310a24b0af772016498e1e0091f7d" },
                { "is", "027ae76f9d26678954e235762163db7fc670cce5e335a7e9f50cfe7d71fa8b65efc912730dddc26013ccac35f79673dd3f0a5d748a945c86ba95152927040c18" },
                { "it", "8d5f388273a97b62cbffaeb139ec7550b387b6bb563547fb5398bced35dc7169687d2f0c905fdb5527dc9ea2c9b15893f30945dfadd99f09a27bfa59b09c8f7c" },
                { "ja", "c29b5b311db306204c3b9b9181835b87fe6dc8601905e473c85300feb2838550843285d6fdc9e4bcd9d9afb09a5e55e3a91b4ea03b0e0fabed574ca955931efd" },
                { "ka", "37c0ceb841aa005695f39c98a1d4f4964c00d68f447b00b7320176c2c6e1b6b0c86fbcf795626b4cd7c2474a0f507ead0fd83b0d7f73344482e3dbd9a58414e3" },
                { "kab", "712a3f00c8d38c42083d335ae40f9e54dea9e8fb140b3fa1c1b37ec03273358a217a418f22b14c4437bb26caf4014b4256cb8e0725246fc038f3893d518924ef" },
                { "kk", "ad3d8d9c2dc3c291794715ddf5acd03a3d41b9f375af15d7722775d1a36463d9167b80d3fe72b225e737beaf4bb449e80b9be19238e9299c2d387f0b13a26c2e" },
                { "km", "728a588ef891083977d15af4a355b8ecd1dc3b09518b775cacd38d15408c421b99c7258d7f75a86ad591c980204fcd1eaa60a7da1f4772a9d6f384d7540ad2e8" },
                { "kn", "0472502d09e3ae4f3e32134cb0534274b305cb54b92f1d2f43fe7d873b54fc90e75bf7420d621b1c895ee8252c1ed80a6f74f9754657c06b0a68a128190fa33d" },
                { "ko", "7dcf108f9b3fb825076594762a4e74a193c7c5001d866d3be69cdc5b37becbda0b63da29e4cfc377d665304bacb0933b447452beb9bdf359f6c73948ce98f78f" },
                { "lij", "02718536f96e640c504104e3d717d8b9b2a1c929cf76c717b5bd44a9aef5f317370cf72db4ac26c7e273592623a4f9a0f57a578873addd7c26599861f3108382" },
                { "lt", "1ffc06bf76dae0e9cc9a9c809817c6e88244271da113fdb91301e7167bf254350278607e0742f5821544f0c8fb376b52affd0dc89665221a38a2b55a221dc0b0" },
                { "lv", "0132ef4167814f79910f0b0ffa088bc1f5de1f32e84081fab18b9c7a013670af1516750542d09954e6f5dd5d1e651ec0ef61f4fba2d53a8611b70196b5297e61" },
                { "mk", "6078a692484135fc1f7459c05612567e9c6905077712daa1bfd0fd03569232af5459a4c8e3acc41207e6cad0208ff5ab7e45edd22d418e49e26046a45c79f23d" },
                { "mr", "79225218ba52eb44da7e5a6a76eb5d9fb37ce3956e9a1f550ef409f6fda3dd09a1a7d4577179756dfe2a39745119aee666b0e31a13bbf0536b0ffef1f1185c27" },
                { "ms", "7e92944a5f33eaa0fb66bc4db8db88896f8cafc869dcf269f1acd3a804e3751ff23ef01ddfd340b14004a3ea9a8249b9cef88d61acb1446cf433a29a041c4736" },
                { "my", "4ac7f0c2de33520c2f94b20fe648683301ca61bc27b2872a7f6305fac5f4670d07a3ebeab348724ee3f3681d5c08d0848cfaf3ea691a614c763e428dc564159b" },
                { "nb-NO", "2ac2e9e9a58c41b8b7251ab656648a867d8688632086a35bfa4bfea7bf3445407ff89a68a0eb46062693bd0ebc70812d333ee7f2cca62781c866298d69657a83" },
                { "ne-NP", "1b28a521de5a7596b2e457238325aa82d7499c6e14dd85c66cddc576c2a7bfcbf97bd59f33e5e840f45c6193005adabb58dc5d06b07581a5690a6d666a1f25e8" },
                { "nl", "41af46cf642cbc773acf2d95428ee447cf9dc4a3efb39e319f98d5b54de9004b0fb55ec54a879fdab95a7f4be203abb87a90ebb1c3a8000e6509e23317fdffde" },
                { "nn-NO", "57dfef66bce568d2471141ed47872606bf83f36c38137e06434a00ca7529d16660c73fce60e2b6fd17b789dbd7b4c37782a058edda1a6cf73005414091878b0b" },
                { "oc", "ea282edf51e61e0a00b4bd902da44f9a5f799ff84e224fbea73c204fc9a153697a133e872f75b358076a068033c21e481f0b5afc8daa23f30932f3f5bde79053" },
                { "pa-IN", "386be46adfc4b6f31ff19d8a38d02e7a8cbc42fee0434a3e908af1db6401d4d977b5df95a5b30b36513e73193ebebaa74f93a58ddb401c98875354f03bdd47fa" },
                { "pl", "2a274ea19afc1388b3da1eb2b65c2757f67d03b0913c203fe899c4d3c62b4247fb7f8e6876f528a1924208c368cedbc020197b93cf4a087d26b8825044359735" },
                { "pt-BR", "5ce70aebc57733a0a878979e8c1e568c58e668ec6a9413c43ae71670d66da22c3d220b6bf1317bf03f98d6f5b230b5cba7f53b117050a42f5cacf28cf28f24f3" },
                { "pt-PT", "05f20fe9df0e90ac6293969fe5e7ca8c5edb1fc93a631fc1bbbd6d028ac333f6facc21020ce2581b54ae8a4a3a6673ca6801cba2be802b9285ee59feffc0ff7f" },
                { "rm", "d4ad04c853dae748f686a5e7dd9c7dbb23666109a4b20f11e29070ee207c115ae33aeb9b67a933c5a1932614e2f465026ae4add53ebdfba864ab1a53b42435c0" },
                { "ro", "a4c729f19a22ca4b36e60c98f7f8a4bae2c6ded652b1ddc03e94f008c60f209af24a2aaf264c614cce7280984a0936f8f02a51a6a481ffe2455ed54e6be9ea61" },
                { "ru", "87f787c846aacea07e143dc1732cb7f31721d5af1b1cd3d51686ad6165942d20439e0ae1e9e51b26263973460215d1bdd8a1e80f18251a81e483890b2abe49e2" },
                { "sat", "f16f5163c163f71f7ac37cd8bb62b97d2a3b26ae922f31b6408129a47fcb11ec7a8161f76d5d5887357262cfa2a1982aabd573c305b088f4cc91584ece16cf49" },
                { "sc", "d5be4d9530838edf73e2fc1270a514129cff9239ed32571a07da7947d9dfdff5e07d51b921b2d734fea020422f0cfaa9e30f62071c8f46011177de97579eb7a5" },
                { "sco", "b249f3dd26e1b6dc12d055dbf3e6eb8a789fbd48abc6d5b0050a906481763f16175c27650a2d9bb9104ff04cb53695f5041087f7fe3282b8409ed3042d85fcf1" },
                { "si", "277f7f65b7d58a883021249ff1f1e8c69c79ec8d099c8d86abac1ee297984fd6ddca0f62c924cfb10fc9d8a118df39adeede06323b3d71daa889f9df4072a1c4" },
                { "sk", "4d3d87852f287f5ab55e39dd4af317b62add368b7120c49644dd39e8acfe1c94250438f97439221a1fbea35b176c021cf260f8c0855d29d6b1d42814ee06bcde" },
                { "skr", "0950d87e154ade98cbd77fe0359a071d15c1570db66b1dd7b99e7659f14fdd8457dc8173f5bba8364305f9148b66e629eebfc3d807b63e0796997c1ea80cbc8c" },
                { "sl", "11711242918523ec622fa5675c14edbaab3dbc859afd460961df56c2aecaad3421d35acb3976e490a8b806548a7f81e242853ae7e78c8dd3f2974712a688a971" },
                { "son", "a5359cfff7b648172ee91c587e0f9c16e32ad922e3168fcdb8d1d5d49ec2d851f7654a155b210c583e5b8b8e122ea76266b126fc7168504ae04d2573f93df95b" },
                { "sq", "4affc9db3fa9052be9e2c0bf4e0e75c5ee4abab55a38c33adc276a416833d320284041f35b22fb23982fac86bf2e029581f595d37d417fcaebfb78996c0c6598" },
                { "sr", "3a5cb28ca5528ac93109cf4c90a553c157e0ee5fcef96de0c83c197015428808751a77bb97776bd6ab6c301e26de2e4d889bdea00f5bf6255f9e92f21b145a6f" },
                { "sv-SE", "e6f3e5e47ab222c90fdc9cd8e82dd3558d1657ec302b971d2b7a5f4b50c61105d45a4237b6aa2c3008c32620839375e09947374cdd4735d773df861b06ed2ee1" },
                { "szl", "4f4d236beeccc057f3e818cf3e8ac016579be6dce90fabcd7adcee5b0a255a861d884fce29012589fce7725c3efb151ff6173daeafb4d045a000ec6e57b4b3f9" },
                { "ta", "1f66a84c9760ccf773c0c538ac6d1a855442496f49d1e34c30855576efcbf2adc63f1549fe0a40ec50851eb90168bad56365c3e2997d770cb77abe388d77ff0c" },
                { "te", "fd8823c8965c61df742058514dbbb6006b2c628580bf2263f71c72a61be4c1411830ce30c43bdf1f18910ff0cc4dcc66bf1b4d2f07669c2988cf3c6c9c413b8b" },
                { "tg", "45040b40eb7881332947b11da4c9e41b7cfbad19485e3d4eeb8d4e66462191468413c999c58ef2b6419e836c8d9f38261e4a80d6518574718561687c67064159" },
                { "th", "121bcc475855dbd51c347a3843c639e7d8303f1af7c545efda1a66836c10d3b5388a264ba5e896502f85cfcdc2430b644592c006a3ea3334b293a8bd19da2bc5" },
                { "tl", "935f5d13621354fb226d833b361811c1a10974e46a9a30b41696c78fe89b697ec7b02fc00871704b0890520634df0592c79d1fa44a7d15799fe6edbd4f4486f6" },
                { "tr", "ebe8ee767e488da41e7c19519739bd3a05ce29f07e5dd3288fd1cc0ef61d69b9454c0ee3eefbbdd501a5f0211639c015ef0755c8dd02e965dcaa963c35f2e3b8" },
                { "trs", "16c377c75a1c0c43a832b7f1e3164505ccb01b36c4f6952ee83670e01d5012157e5c0fac9de3d55af8165c256ad692afa70ea093a6a4d5532e53c7f342dbd511" },
                { "uk", "518eb9e30c07674db23e906a6aed589f7ad5680f61b1ec8bf919caec2a2937fce0f1b2feea9265ce68e00e49fdd9994c5b30c4e7f1b59d18f20880820b51284d" },
                { "ur", "b21a82414679f92d56218891b6323813bcc409f0625ab90ffa094a43deed0af1b2e94a4879ef7ba76c7a1092ec80831f2e324a01a192fa90a80eeb87df5eae2a" },
                { "uz", "5739441e6c827fb41ab6196143d4986024a9a62b8e31aa77598dbd668d87271eb27dfaab4d4addf4aa03a7c93b76fdf1c6ddd907bf8ae8fed818bfa6d4996f39" },
                { "vi", "a0eb353d8ac529661de12fcc245e620d59b8307490ce376ca736f301c571e3fb972518b12f0cd779b74467a74f075657be783830aa9470df311139784b216338" },
                { "xh", "43758ca8c621c3e0a236ba2f99af745a6f1b18272f2328017a34f4f673adedf662960f3575a87106b8af0186184e62501d459f17fe1f06cc6da465b0337f0b3a" },
                { "zh-CN", "a4e29dd1a7dbf8a7520997e6ccbf5ec16999add6174829dd971076fe91a278ce2867d2c1b76674c32cea8f58cd491fba2ee3b0245f3401cd8de5967b15d1d20c" },
                { "zh-TW", "cfcf2631ad9d70b52eedb1198d2f3b90fbf2a405f80ba006ff4aaaf751ec11aa652c44e44539e727f622c050f25969af5ff6b0f29215b9ff62bd0ca3627abb67" }
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
                    // look for lines with language code and version for 32-bit
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
                    // look for line with the correct language code and version for 64-bit
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
            return new List<string>();
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
