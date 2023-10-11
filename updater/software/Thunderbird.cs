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
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.3.2/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ca70ba427f31ee296315af71ba4855fa5530d3cb08d55cbe4d04abb7f05c93ecce43f2389a84b5f6f03f00627948a08ea175bcb981909178bc41bf511a9834bb" },
                { "ar", "1792b8561ef5e02d1a086f31c901c44f2771cccf24313fc09d0eec64a5b1d0cdfe277c34e332c1d15d629f112f231c84ec38758811133b8060d5d37684b5aee8" },
                { "ast", "ca0188496f65559b0b443c95244583c77e8bf75d1ea3222e4924f0cc8c7bad7703d7c66c315e459b027abc26ce7d1d0050159fa80748d70e3c207351685c4f80" },
                { "be", "ac2bdd0c0f28098e3dc51a40ec6084d4ba76f7c763381c1aef15b3d22984aa632884bf66eeebe54d91693d4d7fdeb72e7413af5b67837dde9e9186f7833e23ab" },
                { "bg", "4a2786f54ac87454111a1d4a8adf4ec5c9b506ddc6001efd6aae32ea9ce5170f1cdb0eeefdee159f9d086648fa1abb3c5a28d1d4a1f86bc7740ef72a7e9e110f" },
                { "br", "08f125a3ad92f38f18d06a677067c931e91fb9b08b81b2910fb00400148f1d3dddf5e1ac63ef067cf777888f133205a5c36dde1e13c9a07bd07e753c396ab571" },
                { "ca", "bb8d2742616af675b78b4768b9b21c69af5a4124cdddb9baf2ea18d423db17237af9b2abcf9524a9aff1d339eea1fddacf67479009e4d9e2575d8c57b7685c0e" },
                { "cak", "2c4b88eef31709ac41a1b329fd521d102e18d86a29dccc7fbee5d75135acf01963c1e1e0e31625279004714902901c3a1f6ed599b96290c635989e4e5a39d6ce" },
                { "cs", "3efd081a9dae2184409554f1abcd19259585040914bdf2f88d466c38cb431eccdd08d2ccdee5be7a5d1edda9ba5a15908f5e35b21face6facd6696293fa74ffb" },
                { "cy", "f04c22e6beac47ce7d25a0f6549262e38d9b5a300bc73fd0c15b1a5fd9af2769b538d8d5c717399b1dcddd0ffc789e34538a83a44d463122163d7f47a8c64485" },
                { "da", "30ae02666d5fc81433082894aadc059734db863fee39d75de59ec76e1b2c0b3ad4b5e962cd0baac359757cab95894616f4e52b6436901868c9fd15ebbdb818f4" },
                { "de", "15598ddc661839656126973237149127d70574c9a66209cd09f356fb458a513c361142434126252cb968cdc9eadcc34159f25663fc4a7bdc76b968970e5e891b" },
                { "dsb", "3db7649d6891e43850c91059f2155ec8521f4b80d351e993da969a3a09112616c3100868de7566cc5a7155f6d012aca18ad8f4d3a06611bdf0c6992c7e568563" },
                { "el", "69da7d840ce74489cb2106d5540060a5dc65ca27cf5f49ad475050f33ef75a4b6f1e3417b9ae0c6140fd8fd963206472181d37b00ac447abfdbc3e7fa98c1997" },
                { "en-CA", "87e6ee469f875ad3fa4254b80ed067bf360cf09b25d3ff999f856ab21b990c431b4c50ad67098c617708809226fb9a5711a065389bea30963a86694b674d86bd" },
                { "en-GB", "d8f93c2933fcff29e0f8a1cf8da3edc264f6065f1bd37d8e6c0de938a8f429816b209aef8b784765449308949af151f9b6e5f4e457aac064a5a35672f2bcf7c9" },
                { "en-US", "a701deb61da88a6dd626a21e5f9db2649168cfb258cf85674ec67442294f8c47960167f9c160e9cc90cd8000be1ce84c64cf4e9b0ecdf32fd2ceb0966bb456f0" },
                { "es-AR", "9241b51e91b987f3fb78494148ecc603272f9bac173383b7aab271d6758eb83ff2efaed5cfe5783b9640751dfca4e6f70d74b20ddbd3961c9422ed2a3469ba85" },
                { "es-ES", "fe34af673996772e386e613d07450ba0ffcb34c0b98e6e604ab4979d93fc8606a77d26a32fed1ee9d92e585b7973f450dbe6321253b87a28c582d0298830477e" },
                { "es-MX", "6be44849571f6facf77fb49ab54fcbe5eeba33bfdf205972c437b642c6a23f268c8881e5f521d818f916e715764dedb6e552d628e5aee7afd2364002143c878f" },
                { "et", "04e2f1bd58cdf944870ae13f72578a0f4cd76bdd192601805dc851ddf67a346a5b1275e479b96b0d3842aa7769c3e6601ea775b0e597a880fa904bafefe16bff" },
                { "eu", "8ca835fc28c56d3b5150abc7cfdaf16c69c000a4e9fa9c29098487a89a5bef8748389b1a01b7fdb28e3aee6c68288e86ba599bd552c86a358111f9338ff14a93" },
                { "fi", "c9e4f934abb0eed24856e9ced9382e76b0b7158c027aa38e5d6462e3d4014839f8d031a87c744923aa9267a3d20bce6d1adbb9a6680352c05d4f8b27a6faa772" },
                { "fr", "a003cc92ab82bdd1e3728d6cdb5f39afaa1fd97056f1ad4d4c72f3ca6a8729cb903261f386001a52554791e58735996091713654712a4b2da6d8816611bbe465" },
                { "fy-NL", "7330241f21c154b743ad26ec0a75484e6764e40cb856b92087587dc4e3e2acf71aeaa59527bb9d106d29960d8f7bde706d5e221286b0d219a42f9cf6033747fd" },
                { "ga-IE", "1a9b0f50b4ee6cf9a72f334200ca0e6b40eed31a8ae031cadc3e4b5675d16b00206ccc8bf9cd65a9cbb8d4b6642887a1b2ab96a2a7865a5c04befa94327f4b3d" },
                { "gd", "cbecf60418b6525cf929fa6438d9946cce987d6bdf725a5c8f32a4a67349ab754bf43bc64049eb610ff9c066c0efd1b39ea136a2934d96ca890bf0d69b38401b" },
                { "gl", "ba9fa0f3aa4ef79e9963fa16d9db57aa2139c8653c87abf488ad228016d2237d83ddd48639d22bb5ac3df911c5523d1735dc79b85deb5e7f2a3d9b3171addff8" },
                { "he", "4ebed71d7ec1bc8895b478d20cd80e91aed36a7b672beacae9f7299ce459d96f3c15f176364295167067ebb6970f77e2e037e680d7b0f28f3973de034e0c65bd" },
                { "hr", "6cc0298b096c91b4a7df51f496aaed379dfae7ecd18ce0aee5abdbc0b7aa974af3b5e0d0c2e6dac314de3c888ccd1c9bb9b0ddb49e5a284d3d733143d9edfbbd" },
                { "hsb", "9878179d34c563ae18be92a88559080201b95ef4081ba21817676dff2b64923fc1f03799552d3cb87aaeff30e04d7f14c653afa18960bcffea57cd6ac93e7b45" },
                { "hu", "bdc1908bbbcfd1d533cb5e929f949df20d4ab9710cc9b1959d0b935635df25e824e3b6d67acbf4f0da54144b07283d942ef602273e316a68810b26dfb592e03d" },
                { "hy-AM", "5fa34bf770bb98fe3056fd96ebad0a2ee0c7f8562095142193e7af73e54a9877247ac5063b391bde226c360ccfe7f699ce6306ffb406f66bdd16645e8e57a1e2" },
                { "id", "06ed0826abe6d255f1b6bb170dcb9fe08a268ce0cdfc0debdbd5487703a64e071725147543acba1680c4c1a6e43aa6e5ce1f62097e23cb26e4e587de70d34b08" },
                { "is", "95bcc117ac87eb85c4ed11e6bf6d949e13ef8d9ff2e9db88904cba5ae8d59975ae0485fed77b12890b0bbedd259689ba5e862a983d622443d01216218a31cbf0" },
                { "it", "d9213d4cf67a909be13ee179dd37e81ac409e2ce5b0db3f38127cea15f295753c8cb9e000ddd25e9f1b32cae06689b49ebf3d3228c94c80e1c6d2419d59454cf" },
                { "ja", "2b0419fe15ad4139b855a1154042ba9ca1c733a3324ecac97e7f018e95e93822ce9b52d81d7a26d84dc4c0a49bb3364c1564be47a5651189a2073e04365519c7" },
                { "ka", "0edb04e99a3f180362d74393cdcb135b22cac99cada9b6e3186566fc8dd2e3f7e5133610515fa8cb252bc5f90cb402b45c9db6ee277960aaaaf0371ba0f9dbbd" },
                { "kab", "e0599b28acc7d6f033b98d13426f548d3f42903f4e67098fadfb87f707be5df2779a2d6f31421bbd85e5cbbc942266bf8fe7b3dfa602f3dccc55b476c4873beb" },
                { "kk", "bc88a40f7bdc8cce68902ac5ba043ea706898ccccfb2c8881f31d9a29f6f42927387615df62c0a6b868f5336a086b570f10cc86501bac5a51f02dc9d96d1fc15" },
                { "ko", "87b4773671225f7f57637923d58e7b36381b088aabb2c164105165cb3fa0fd233f639e1a19b37a9a5f4669b49196a699ee54dc1f4cbe366974e970de73e3f0b2" },
                { "lt", "57c0f460c9f2acfb1836dfda58565fe40f7adef6b60d1b5188c62398dfe1743e2415f6b272ac0c0dd51d28d2648422830e9ab22c3f6aff95ded6bb51d9770424" },
                { "lv", "58b03c23f34734e618676b442767d44213e72970cc53bd596fa721e35b0ca36632d65221c018b7a8790152fd51a48a0d805cc653f3385cd8bfcbf8b9549a8e9c" },
                { "ms", "679fcf50bd322f38a6caf9614f17843ede057235c7840363b248341fbc2adcc5b8a81e9eb7407bc9c9a1cf49a7305bfaaef02cc89498ac85d7895ae9ac52b973" },
                { "nb-NO", "d7ac586388bbd434340751de0d43628e1b3ba35289576cd6af975e5c442fbc85af7838ae9ab45eba52e86439c8361e522e1d79e9b3d3a8ada1e9789dbc0bf1b9" },
                { "nl", "32dc39646d81087e2e222d8c9f1d5613a470311af1b86664c9115c5ed1a26f8a4acba646e9a89038090e045c03646188a2c872df676e82ac34fcda04288d311f" },
                { "nn-NO", "e7a35d82fcffc85bb4c2789caeccc6e171d6d39f43b991a350286243a206643c9de12c4eaa613053e2cc3e1a93ca57db6f4162c8f12e4e9153a7c0d1da09f3a9" },
                { "pa-IN", "842787a01eeb939ca731bce1cecb9211d00113c9e3cdd38f47c2c0c813c47328e40b7ad0a42509a6aac3f23b057e31d4927356907babf8d59c1d1ba24597da62" },
                { "pl", "6596dd48be56390a213efe94d6bc7e271d588fe995456cb113dd00632316d17aea9b2370fe87fcdad2f0d54a213ff55342c3e547db3106a06b729ad4b230fb36" },
                { "pt-BR", "d313d40415b6ae2841c239875072a50c2de0451cd3aab29cd1aae595b3638a8be6dd1b37b82973daa0bb9bc1a4fc2bcf81995d1f3295b56ea68296e4bd377898" },
                { "pt-PT", "bc98e9d976a6ee8f828ad4997946f71ef26fb73a9f26e66cdf9b062a0ac3e7442bb165d58666afa93a0d3d3e504b89face9250ac047f067a3d7b968d3c15b22e" },
                { "rm", "b526f492ecfbe76eb3bb1562ae16b7adc63ec645c1907fe3728f696b970f9963d75ff8e13fe796aafb5545084338ad5ce478a30ec7b15ee331be149b0b673bbb" },
                { "ro", "e3373f5a59bdfe08f9d9242423b641a58604c6d2b9d619935af5ba3cb85c0a48e27ab265a74b7e82db695ef4e1a144fca7475841115b55075ed55097719e1429" },
                { "ru", "1297e9ee97e2b98ebd786d3cad0a02d8cb859470c191b7608485e5e18ad1d60a54394070ac3e81eaac34bc169ecf63d8fd693166ab377a11359c3bd10fe5b83a" },
                { "sk", "1d2a23377aa6d6065248403a8d05b6bb07f69662136b3dde1560d95012ec0ac11d972ad8fe596705f0f3c4a89cb192567ce9106c44db0fe0df378f03ed320495" },
                { "sl", "0be45f14f540decb4d4f079c4d3bb560de0a64dfd80d3e252b661e8364dfa206de5b29021125d43bad241cc9cf5cc6c93249bcbab09863a8882aeb0f7ce88653" },
                { "sq", "98ac3bd6793d48825dcdf66c4f748db448bae5751a31ba2944c2c1ebb14fb013fd75027708b01efdf1dc15b25cdfdb99c95469e69958e3155a0928c71af1b380" },
                { "sr", "0536aa21e0030e42f5205dc65dea0d59300aca87cda675d1218981f011c83d262fbd3c9e6d36ad844f1a8b28f796dfc5b3b2676731187523811b76d275850e00" },
                { "sv-SE", "8224425f9dec96c97c9dde3a34fd8bd17d31e397c1a974a4822b5948ee0d9071ee062746e9a49818dba938e6b245c04e2139780f504040a1345d4382fcf4ae33" },
                { "th", "ec317b35c551d586506de1b9e7e0241c5d17264e17662df269f3610e72b7b8f6add004f69c07614396cb9984f084dda8da5335058aa6ec118cb0d53afc22a54b" },
                { "tr", "a0179c9a22d0b7683067d71d9df69a0a5ee00955a5562576030b84bfc5733597b758522828866d6d27ffc34fbbf5f34e2a2a6df7a673b7219ca4f9e91fc9a982" },
                { "uk", "f86b13b10acc93861315324d4c95b1df0f8b32de0b0fdf333e6370857f68ac24d817d47199fb6c525b293c11b9ff64fa7fe87a8f5cd71080b085bb1577edf990" },
                { "uz", "b0c0aa30a7f12be6d2e080ad6a73558ad903550736b4e9c71414794c14cc87fa1a775799a7bdfd34186547637462b2bc085ba720d5e403c806ab4ae4a9876b21" },
                { "vi", "056fa970a47b85f8b912bcfe237a627dd2e1b0c37e682aa2dc8187284049bf118531ca89f90c73c55c10171e02bc6fa1f4ca88ff97de200b0bdcbc45e554f828" },
                { "zh-CN", "eea27bd4ff2cc7b845ae0b1f3f02533d1f2fa48d28454521c94adc67540f7696f8a0b6996d1c941e4d7341c64e5fc0bc1cf7b4b97151f787dd129ef0364dfaca" },
                { "zh-TW", "4371ca85881e3c25554ff849c026d0426a48a3dbcaacf7f23c1743ac5161e75126bdf800f5941aba70bd5ed3aa650e90e53fa1b02ee284566d7fcb6f7f95526c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.3.2/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "dd0cb722974e38014d89a262faf0deec076c00a0c5166a9bc9c4bc75d579153531ba8583bfe0e9fab78cdd11a497933d489c1ddec86b01617fe8dfdc7c8cabbb" },
                { "ar", "405711a418ea5fc595da3f2acc27f59c0e4016d6ac31c221ba7f4d203414c773114dfdbb16a453afc53a6f19846ddde699bfc4848fd81de1b900cf7ad20e5c9a" },
                { "ast", "f45a7f47e93370b7687b5cbaae3331d4bf186ef06ae2521dfad36277c836f5264f5301fbee09f9021e155fcf897cde8c0e7688f62dc94187e948bf48e57b973b" },
                { "be", "01c603c9cd72756634a806f8b2a842be1436754192af48a48460302aac0a3aaf5a3dbf06b5513c66cb911178e950ad24b534a2cf3b18e27c9e488c90795f6d19" },
                { "bg", "6b4ec5cc2856c0b41a657edc0b4e8333d973974a67468a417316dfc61da37c9a3ec1e17ac0128b31f7a57e3716aabc6337f7e8a595d6c0bfc969d112937754b6" },
                { "br", "f344e56d1c06a5751acbcb8adf63884ce55b475302403f2f9946284fbf27aad1bd2cbdbfd4646c81de5ef9a528a6ab2a7a6852432a42bed7a0dc1510edfd9bb7" },
                { "ca", "37d0dfc281a871f3f1f54e55f7b9bd9dbdca81e39f786f6b6fa4da11d8513d9ce26c355d2528b1260e07b7faeb3108396aa3a5b28a628f2f570f6914e428350d" },
                { "cak", "76ecfebb6ff723f6c83e8314e45ea8e4dd4235cd9b2e83cba724767712e616c19ca6110703d2a7e874958d552375d6a222b88cd47d8de969d72bd7ee9a83cead" },
                { "cs", "f10378733919ddceb17b22383632f28b1b1ae5d8b125f3f65b7d34e931087111439c617b7396c39a40fa5e47a28a455fabdc107985bf63b961843ce56068a017" },
                { "cy", "ef14e6551ec2325ddff9ad5772a0db47623feb9ea2974426e93bbb3b5784e9da9503d5507a6375a99bdb6d0065539210d8e43dcc8409a7b4c93ce64c63d71938" },
                { "da", "746152285a23c8d8391e1db834b2ec8e32ad6c0a54913071c8853214c901a423429c75beeceaaa3e1e12e37252b914253f147de2ff0fe424f0dfd12a8ad83488" },
                { "de", "9ac7af483a40fdc15b544d9ad23115d76744bfdc4b01920207bdcb08bc80623434a650f321770dde01789c4ae9a70b08d2522ba41cacd6917258bd3b78087f92" },
                { "dsb", "5d7269667e31002483c736e5311c043cf62838f394e69d29b7f18d01e3ad0097044c171bcbb4de22dceb807e7f18372ab56f0bc3f138c1214187f4acd7b22a37" },
                { "el", "cb0ccc6c0191e9dca9523881343779acd398214c18e7408a87d28a7ae951e87e81e4b1f41a878d3f37c8122936ba2b40e9236817769f61d551adac6dde5d8184" },
                { "en-CA", "6e0f8cf446519a8dc7f85fc160bebe6627c122aa1f69cee574643f5ab5d4d72c6d5fe0327755eec6f1a8957c78c7e7e285c4e0e599fce0d24ef8755bd11fcd5e" },
                { "en-GB", "e10669813451507f243ed4759216dc57b2516846d47afc2fa30940d007ae51831cb22ee368e080fef452b80699790b6a1eea34701923e66e67546cd7e93c4eaa" },
                { "en-US", "5b49f4f9d0bf335a64abd8013f5e62b831beed03749d9853ae11f759bd2b1cc11757e6b7f5d75ad60de25fa107d7c4b856c09de3ebbde3f355f9ed9709a088d9" },
                { "es-AR", "5693d89d32696a4699f6a0fab540fd462f8089e5851f2e73811846bbe5df2dbeda57439d2fdd2091e07be6b92875df0d79b5664110e3f998d1aaad79120d3a35" },
                { "es-ES", "d33d4bb873f5bf44f5f1668c144c657de92dfdcd7fa53298a273c874c570e53be2a172c05ff6a806521341701ff69f776a172e85753b5ad2617a3a92ffb184a8" },
                { "es-MX", "45897b747ac7e31b201414479fd1b2eaacfb0ef5c68596a01cfd899b9d62ff67071fee624d854c3380d9b82c3d5aa70b1d26353ca2b77edbf6a53c4af6f2272e" },
                { "et", "3085769036e00158ac44b4d4f50087d6cd44ec97ce64b5d69429fb3c7f0077594b17b5109b035f7033981bd5c682eba8cd9e4cea8ed5cfbe3458df0c920624d4" },
                { "eu", "f4c8ff1ff67b1bcac06c276a88576d7a121871a89b6ee41746c7958ee809a814d0a92ceae53ab07b674a557f543a76e09d1d5daf5125af33892b37ccc2ec48c8" },
                { "fi", "efb1502550d2875f1be5cf10f53dd2b6ec10c6070e1b28f8d43b750635e2574e7fd8f186fb3b686f1230c5984583f6ea56a769e663a9527a1e6df085a9ad0147" },
                { "fr", "f4e99243dc4633f2b42e7781868c55553613b366823bf1bcd7327be05a1fd17132de1f1dd663923b5b504eed6ce46334dcd78d15a3fe64276ed940ea45917fdf" },
                { "fy-NL", "4da041aaf16f504be7ebb9744c0dcd709bc6ee4740026a40d8df46f750519dcfcb747cb71cd942e86fa46a7e807484ecaafd615b7bfbdfaca43825c0f01fa797" },
                { "ga-IE", "6ba0e7bfd2dfd37b2df1dffd25981341191f8e5707df04ffddf801e3f5cb7b665c077cc21ca8060e1908876787ffbe73dc519d1a67e3484d2dbc4080cf5828c9" },
                { "gd", "ca18b0195f6d2b7032842924e8c3d274322ac244b16812123db2a27c603eb9404d68090c0dffa9ae30db94e79564c603eeefc73b7a3faaf8f522061cd76c0cb4" },
                { "gl", "1708eb0bbdcec0d63925f27fc1c404238d77832f240633c53a86343316078cd5c4fdd3faad98d9342d67d80300d649f1d85de56a1ff9b2baece25aaffc1ba423" },
                { "he", "abeaec9f10571c02b0e7db9b97a973a576cca703b74571076d4be1174004d96218cc06e29c3c13f7783f55974720bcd246a0ca0c1b30799549eea37d9beba71e" },
                { "hr", "ed58a0d36f650f0d33d42f351412f8ddf63f092ff392198633be8fa06d1093d4c0cfb37575c112c0de92441725dc5cdd6d60b093d799a82b0ee7d33155757611" },
                { "hsb", "a52b9c0418fcd73926bf76c1f165ef1ef5f5cc4f49776cdfec643aee4bbbf781e46ded549f88a782c814554c68d512cfef5e0814dff15c0a08e8296643cf8282" },
                { "hu", "850d3435c80a28f9e769e866c413dc082ce8830c85902e337bc794d33054c58bd72adf5788755bcd855bfed0b13ec664a4676a8b90325df9e9a13ea5dfc5bf1e" },
                { "hy-AM", "f5621d39d8c6b8372978e13d59ca6ea91134633b46437013e54b4b1eced0c371ae8adbcc1970d386932e4f28e5e4c337164fd90a60d388f4661978d6179c0809" },
                { "id", "46fcb4233ef73f8ad0f56f9fa9ace5fdbfecaae9c086469b2178683a11f94808bc3e1c94df74326f55667c94c69ee30f6897956f1eb10b9b3f2553a39a5be97e" },
                { "is", "64cbe282d0c87f066c79b8347fd009c2c4c1f9b74c7a405d84495b5b76e465874e464717afba76e3fee0c8016a0b043cdd360bb4a41395f9a0bcef12026fe102" },
                { "it", "8fd8f8ff3d99a130a45471c7a1b288b1a5bbca1f0ce50ece463224bd2924c0cb21a77b04ffce123b8728684f426692def2841f061a8fd14e698d79e4b83573d7" },
                { "ja", "cfe15533fd06b54233068aa8e4c62bfcfbea79a886a37a7cf4f28472cbfe24b1ae1dc9e5713a11ef678586d69d5d8e6f788a4933621de35b7331d8480e1b6127" },
                { "ka", "0c3a203d9deb5dc24a09276800151a32cdd78dabff95b423c3bb5172e5103fbf537d8f413e479299e5d20a5d6f964b8384ef3e933990c4152ddedea100d07158" },
                { "kab", "ed93d91a78e6f3dee75d426ab21e9ea734b772b4f6af712173399cac605d2e0a5f502c63d3de94dc05f1d9e60679a999d119845c104c7a9721ec5f207ef2ea02" },
                { "kk", "4ed7b065d87998ff3358e939e296dba2f6a7c86d980d8cafaba6eb8c6602c8f25d3da01c49bb8e3a80dee060c59017b06271051d757017c24a173a96afe3ef1a" },
                { "ko", "c1830b4056c152977e3d076ab5ffa6d3a0d4e933b45336158f6cc10ac23c399eccd6c6edbb7591cb75f73423cf803f82478638f7710b95f1ea897f7eee104c79" },
                { "lt", "d4dbe4b72008ef948be070a79f43b2272c802b99b7deda7d53721db801304f9fd26885e9151fb4af826bd00ae353cdf09d4a7b7536b837079dce3ff4be49e74e" },
                { "lv", "bf2d3ba9cc6b941deaa03c62ddc45f722a406748a977f85b779014f90ef6a3743ac8d69aa887090cefb8538fd3102fee61502d3dc5419e263dd40382882d374e" },
                { "ms", "0d4bc9d7cfb2cba2a90c5ac9f353b93de85a6d321d96aedf6f442fa1c24e13065398bedafe3629d27f6693623b4d425e4801df3af3dd102e40cd7ee5aeb02311" },
                { "nb-NO", "814ba4701e5413a0af899b1ce4f791a7b6691b870f4d2ec32391b4302cfd7d5a890a0110083bf407f4efd11fb16de1c9b1259b97502f9f75c4f50dfebb2b8d57" },
                { "nl", "b9aa5c3b5969f3bf3382ca85d3d831e8bda047517d1af68438ae87f90d59865605154e64de280126f865f53ce99bb8555b34d670fc545d213e3d068b23a3e3b6" },
                { "nn-NO", "391b5f83e5bf78a3b01800e4d6cbf2fe6122ca583fe20c9c00f7e12f3ceee86687d4c87315c734d3477ba0467c4413f1e40e665527a98df825c5c8a75f196176" },
                { "pa-IN", "57d17baaef98372e4797f9aeb8f1c8450ab92ecfe5fc23bb74df3d010e68f342a9413bda53c094924a1fa227d988fdb158863bb854192e2fc21957ee37915017" },
                { "pl", "eebefb89c8b003241dd2c7594675d9d189a849af2f98da52d9a6a727b67b19706ccf61859c0e875902be78e8de2e50a21e5590741fffb0941a5d73be849c1f6b" },
                { "pt-BR", "0edb65d6b3cf4bca919d67f14ba2987e0ba4ca4b4da7a4101fc5e44941238ed13df75e9fb9df3c307119910e5bf35fb2c2889a7c4b07dc68a223de11794c7e74" },
                { "pt-PT", "7b130a1de56e7eed88a2fed2fd6d09b8e2ea0e66a22041bce2bc45e0ee094f916b4c15ff156060fdd50d25081f202cf6566a9f11149c48f0805c4ebac2564962" },
                { "rm", "ee5c292b6510d0a4b26f58dcfde4d8026131b5a103383de52ca36f754b78bba97943e5d3e117e0b54648eb3063fddb868774b7815fa07dc827372c14789e695d" },
                { "ro", "93cb3a3204be5185394d2408039b798ca7627b0daa2a4b827583d529be126867310311c87ae0a9375afe2dcbcc0c36cc44776eb5d1e49add2f0b842ab3f1cace" },
                { "ru", "269adfd9141313808a9d4bcf20b9ea55b3689e1693630432320931b30cadc107cf0f20e69d368097a705b82e3e8c95211edeeb403cdbe45e64ca04436ee25f8f" },
                { "sk", "fa8a4b5af3e9685b25fc7e3c33cdfaa976a7fe1561ce94191b4ef48935a18ff3a17ec8ddf68bd33b176bafd67cae526a06676261816d8eec553c7d2ece760e8a" },
                { "sl", "809a552bdf8eca289c9a84eebe6a518767441979cfc40f68e53f78e59b7db3eb76e22ad29f59dcbe4ac3444700d5062f8b80ba1ff006aba3aa99509b25fb7f45" },
                { "sq", "ec233985d54cb36065483570805201c9a12672a3356e3fbe20e08b7dd0f8f800ed413b1115d9d8b9ad6cb3241dc4b0ae57f5c5c9991a769a62ed7176f1d26346" },
                { "sr", "09935702831a244cc60b14fc500a600570aa7abed19494cb2414b860b40a90c81d369e09df60bc0aa31b8a68c9ad80162f58fa8bb13736d84f8615560c18600f" },
                { "sv-SE", "b8961aed0d3af9d31ef971ee0532f01172009cba9dffabc153a571bce44343bb514eb433ee7095df1bcf2401be4a06cd92f48e64ee56e43aaf59cdd70ee46224" },
                { "th", "0460a5fff1d75811f36cab013640a90ba1c6d0b9997f1b7fd481fad94fc86be0a403460a4c493c0cc04929b7b41932e192fdb45922d81d8e3dbfb48ccd26dc41" },
                { "tr", "df19299dedea7b14efbc64176690ab2437d965a8597530a4ba6e5c5b153d9d60186a0825bce79250f1e7449769e8ab6eb2af3b982129f98c414841e1fcf1618d" },
                { "uk", "72b1c17c81fbf58f1b204cf955e8a21b2d733cbe64f28c589b62bbcf572f680691a9383172c0c78dfe9a591b68c6f5e783efd0dad32accbf8e9bec106b59ca2a" },
                { "uz", "3ccd02b884544232d402b4ac0af65b4240ae34fd8e8714c62c60b66936fbde80f2d780cbda047cf056e16581bab9d00b59027c8494b9fcbf4e2f02359ec69c07" },
                { "vi", "c682b3637c4d6c851f81b2547afdf7917048d906045409b0d7f424dbbba389580e1fe49fb8901387f3db27f3cf74ecd1f13f470652e0e6829176d118f5f96fc1" },
                { "zh-CN", "a24597884ffcec237628473e4fc04020119dfbcdc1493a13e3d2e6faf8b29c4ab94f3b4bd1d9f5e0cf0ba33f2ed811a2d1175253c0c9adb4c44027c7d4159c25" },
                { "zh-TW", "028219c713037e37a2a6cffda48ba338c243b8ceef5126beedd7e140a15bcf3fa5d71c6016c09cff58cbcdeed7723bf8881999068647102c43b1eafc4adbdf70" }
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
            const string version = "115.3.2";
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
