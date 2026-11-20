# Photos pack: sources

Accessed 2026-11-20. 140 photos from Wikimedia Commons plus 10 generated screenshot-like images (150 entries in `manifest.yaml`).

## How the photos were found

- Source: Wikimedia Commons API (`https://commons.wikimedia.org/w/api.php`), `generator=search` over the File namespace with queries like `pizza filetype:bitmap incategory:CC-zero -MET -museum -painting -drawing -illustration`, `prop=imageinfo&iiprop=url|size|sha1|mime|extmetadata`. 95 queries across the schema categories; 3,780 candidates.
- Kept only `image/jpeg`, long side >= 1600 px, and `extmetadata.License == cc0` (LicenseShortName `CC0`). Every selected file carries the `{{CC-zero}}` template (it is in Category:CC-zero). Licence in the manifest: `CC0-1.0`.
- One candidate tagged generic "Public domain" (`PD-ROC-exempt`, a Taiwanese official-notice exemption) was dropped because it is neither CC0 nor the Public Domain Mark. No PDM files ended up in the set.
- Title/description keyword filter (people, portraits, museum objects, logos, historic scans), then a manual visual review of contact sheets of all 220 shortlisted thumbnails. Dropped: identifiable people, artworks/sculptures as subject, brand logos or storefronts as main subject, a memorial wall (Stockholm 2017 attack), personal-name signs, museum interiors, near-duplicates.
- Client: User-Agent `SandroidResearchBot/0.1 (dataset research...)`, no personal data or contact address; API search calls about 1 every 3 s, thumbnails for review 1 per second, originals see Processing.
- Openverse was not needed: Commons CC0 alone gave enough phone-like photos.

## Processing

- Each original was checked against the Commons SHA-1, checked for the JPEG SOI marker, opened and `verify()`-ed with Pillow (JPEG or MPO). `original_had_exif` / `original_had_gps` come from the original file's EXIF (GPS IFD with latitude or longitude).
- Size budget 400 MB: the largest originals with long side > 3000 px were downscaled in a copy to 3000 px long side (Pillow LANCZOS, JPEG q90, original EXIF and ICC profile carried over unchanged). For those, `sha256`/`bytes`/`width`/`height` describe the stored file and `sha256_original`/`bytes_original`/`width_original`/`height_original` the Commons original. Originals are not kept in the pack.
- `width`/`height` are the stored (raw) pixel dimensions; EXIF Orientation is preserved, so some files display rotated, as on a phone.
- Some originals are MPO (a JPEG with an extra embedded image, typical for Samsung/Fujifilm phones). They are valid JPEG streams (start with FFD8FF, open as JPEG) and were kept byte-identical; downscaled copies are plain JPEG.
- Downloads were rate-limited by upload.wikimedia.org (HTTP 429, Retry-After 600 s for this generic User-Agent); the fetcher waited out every Retry-After and paced files 20 s apart.
- Privacy note: many originals carry the photographer's real GPS position and camera data in EXIF. Sandroid must rewrite or strip EXIF before seeding, as planned.
- `has_people: true` means a person or body part is visible (crowd from afar, backs, a hand or arm at the edge); no file has an identifiable face as a subject. `country_neutral: false` plus `country` where readable signage, script, plates or a recognisable landmark tie the photo to one country. Many neutral photos were taken abroad (file titles name the place), but nothing visible ties them to it.

## Keys added beyond PACK_SCHEMA.md (proposed for schema v2)

- `file`: path of the stored file relative to the pack folder.
- `original_had_exif`, `original_had_gps`: what the source file contained. The schema's `original_exif_stripped` is ambiguous; it is set to `false` everywhere because the stored files keep their original EXIF (Sandroid rewrites it at seeding time).
- `downscaled`, `sha256_original`, `bytes_original`, `width_original`, `height_original`: see Processing.
- `screenshot_like` entries use `licence: authored`, `url`/`page: null`, `indoor: null`.

## Generated screenshots (authored)

`ss-0001`..`ss-0010`: 1080x2400 PNG drawn with Pillow (a short generator script; not shipped in the pack) using Pillow's bundled Aileron font (CC0). Five chat UIs, three order/receipt UIs, two notes. All names, shops, amounts and messages are invented; no real brands or logos.

## Counts

| category | n |
|---|---|
| document_like | 11 |
| food | 18 |
| interior | 13 |
| landmark_generic | 9 |
| nature | 18 |
| pet | 13 |
| plant | 11 |
| screenshot_like | 10 |
| sky | 12 |
| sport | 8 |
| street | 15 |
| vehicle | 12 |

Country-neutral: 120/150. Originals with GPS EXIF: 64/140.

## Per-file attribution (CC0 needs none; recorded anyway)

| id | Commons file | author | licence |
|---|---|---|---|
| wm-0001 | [20190221 124822 Teremok Receipt Квитанция.jpg](https://commons.wikimedia.org/wiki/File:20190221_124822_Teremok_Receipt_%D0%9A%D0%B2%D0%B8%D1%82%D0%B0%D0%BD%D1%86%D0%B8%D1%8F.jpg) | Rakoon | CC0-1.0 |
| wm-0002 | [Menu du jour d'un restaurant asiatique lyonnais en 2017.jpg](https://commons.wikimedia.org/wiki/File:Menu_du_jour_d%27un_restaurant_asiatique_lyonnais_en_2017.jpg) | Benoît Prieur | CC0-1.0 |
| wm-0003 | [Wilhelma ticket Sep 2017.jpg](https://commons.wikimedia.org/wiki/File:Wilhelma_ticket_Sep_2017.jpg) | NotTheOnlyDreamer | CC0-1.0 |
| wm-0004 | [Invoice 04.jpg](https://commons.wikimedia.org/wiki/File:Invoice_04.jpg) | Shams948 | CC0-1.0 |
| wm-0005 | [L'Oro di Napoli - January 2025 - Sarah Stierch 22.jpg](https://commons.wikimedia.org/wiki/File:L%27Oro_di_Napoli_-_January_2025_-_Sarah_Stierch_22.jpg) | Missvain | CC0-1.0 |
| wm-0006 | [CA physique de février 2020 de l'association OpenStreetMap France en février 2020 - tableau.jpg](https://commons.wikimedia.org/wiki/File:CA_physique_de_f%C3%A9vrier_2020_de_l%27association_OpenStreetMap_France_en_f%C3%A9vrier_2020_-_tableau.jpg) | Benoît Prieur | CC0-1.0 |
| wm-0007 | [Littlewinds Favorites Indian fast food menu at Mahkato Wacipi 2023 cropped.jpg](https://commons.wikimedia.org/wiki/File:Littlewinds_Favorites_Indian_fast_food_menu_at_Mahkato_Wacipi_2023_cropped.jpg) | Pingnova | CC0-1.0 |
| wm-0008 | [Ticket 20220724 110102.jpg](https://commons.wikimedia.org/wiki/File:Ticket_20220724_110102.jpg) | 01x07x2022000 | CC0-1.0 |
| wm-0009 | [Shi Jie Soymilk King e-invoice FN16720614.jpg](https://commons.wikimedia.org/wiki/File:Shi_Jie_Soymilk_King_e-invoice_FN16720614.jpg) | TonnyTW 0907P | CC0-1.0 |
| wm-0010 | [Death Valley National Park - HCP - October 06, 2022 - 009 - Furnace Creek.jpg](https://commons.wikimedia.org/wiki/File:Death_Valley_National_Park_-_HCP_-_October_06,_2022_-_009_-_Furnace_Creek.jpg) | Vulturesong | CC0-1.0 |
| wm-0011 | [GZM bilet jednorazowy normalny 20 minut 2026 b.jpg](https://commons.wikimedia.org/wiki/File:GZM_bilet_jednorazowy_normalny_20_minut_2026_b.jpg) | Abraham | CC0-1.0 |
| wm-0012 | [Supreme Pizza 20250215-170829.jpg](https://commons.wikimedia.org/wiki/File:Supreme_Pizza_20250215-170829.jpg) | RegionVisitor90 | CC0-1.0 |
| wm-0013 | [Poke Bowl Kureci Maso Zlaty Klas 2025.jpg](https://commons.wikimedia.org/wiki/File:Poke_Bowl_Kureci_Maso_Zlaty_Klas_2025.jpg) | Mojmir Churavy | CC0-1.0 |
| wm-0014 | [Honest Burger with rosemary chips 2023-07-21.jpg](https://commons.wikimedia.org/wiki/File:Honest_Burger_with_rosemary_chips_2023-07-21.jpg) | Andy Li | CC0-1.0 |
| wm-0015 | [Latte - Oui Crêperie 2023-08-14.jpg](https://commons.wikimedia.org/wiki/File:Latte_-_Oui_Cr%C3%AAperie_2023-08-14.jpg) | Andy Li | CC0-1.0 |
| wm-0016 | [Ham cheese bread 2023-07-09.jpg](https://commons.wikimedia.org/wiki/File:Ham_cheese_bread_2023-07-09.jpg) | Andy Li | CC0-1.0 |
| wm-0017 | [HK SYP 西環 Sai Ying Pun 德輔道西 308 Des Voeux Road West 食神麗宮酒家 Chinese Banquet Seafood Restaurant food 紅豆糖水 Red bean dessert soup bowl n white spoon January 2026 N13P 03.jpg](https://commons.wikimedia.org/wiki/File:HK_SYP_%E8%A5%BF%E7%92%B0_Sai_Ying_Pun_%E5%BE%B7%E8%BC%94%E9%81%93%E8%A5%BF_308_Des_Voeux_Road_West_%E9%A3%9F%E7%A5%9E%E9%BA%97%E5%AE%AE%E9%85%92%E5%AE%B6_Chinese_Banquet_Seafood_Restaurant_food_%E7%B4%85%E8%B1%86%E7%B3%96%E6%B0%B4_Red_bean_dessert_soup_bowl_n_white_spoon_January_2026_N13P_03.jpg) | EVOW Sahgyune Paiem KAASEI 02238 | CC0-1.0 |
| wm-0018 | [SZ 深圳 Shenzhen 福田 Futian 七鮮 SevenFresh 超市 Supermarket 生果 fruit Blueberry May 2024 R12S 02.jpg](https://commons.wikimedia.org/wiki/File:SZ_%E6%B7%B1%E5%9C%B3_Shenzhen_%E7%A6%8F%E7%94%B0_Futian_%E4%B8%83%E9%AE%AE_SevenFresh_%E8%B6%85%E5%B8%82_Supermarket_%E7%94%9F%E6%9E%9C_fruit_Blueberry_May_2024_R12S_02.jpg) | RagmmIO 6YAHAOI | CC0-1.0 |
| wm-0019 | [Salmon sushi (20250322).jpg](https://commons.wikimedia.org/wiki/File:Salmon_sushi_(20250322).jpg) | Fumikas Sagisavas | CC0-1.0 |
| wm-0020 | [Two bowls of noodles, a glass of wine, and a mug of beer at Kalandak Rooftop, Tibetan Colony, New Aruna Nagar, Delhi (2023).jpg](https://commons.wikimedia.org/wiki/File:Two_bowls_of_noodles,_a_glass_of_wine,_and_a_mug_of_beer_at_Kalandak_Rooftop,_Tibetan_Colony,_New_Aruna_Nagar,_Delhi_(2023).jpg) | Contrapunctus-1 | CC0-1.0 |
| wm-0021 | [Vegetarian creamy pasta - Jollof Café 2023-06-28.jpg](https://commons.wikimedia.org/wiki/File:Vegetarian_creamy_pasta_-_Jollof_Caf%C3%A9_2023-06-28.jpg) | Andy Li | CC0-1.0 |
| wm-0022 | [Coffee and white saucer.jpg](https://commons.wikimedia.org/wiki/File:Coffee_and_white_saucer.jpg) | Douglas Perkins | CC0-1.0 |
| wm-0023 | [Acre Pizza - October 2024 - Sarah Stierch.jpg](https://commons.wikimedia.org/wiki/File:Acre_Pizza_-_October_2024_-_Sarah_Stierch.jpg) | Missvain | CC0-1.0 |
| wm-0024 | [Acme Burger - February 2025 - Sarah Stierch 04.jpg](https://commons.wikimedia.org/wiki/File:Acme_Burger_-_February_2025_-_Sarah_Stierch_04.jpg) | Missvain | CC0-1.0 |
| wm-0025 | [Latte - MOGUMOGU 2024-04-29.jpg](https://commons.wikimedia.org/wiki/File:Latte_-_MOGUMOGU_2024-04-29.jpg) | Andy Li | CC0-1.0 |
| wm-0026 | [JP 沖繩 Okinawa 那霸市 Naha City 國際通 Kokusai-dori shop 沖繩自家製生麵 Yunami Sakashita-ten 板下店 Restaurant food 豬肉 Pork 排骨麵 rib noodle soup bowl February 2026 N13P 02.jpg](https://commons.wikimedia.org/wiki/File:JP_%E6%B2%96%E7%B9%A9_Okinawa_%E9%82%A3%E9%9C%B8%E5%B8%82_Naha_City_%E5%9C%8B%E9%9A%9B%E9%80%9A_Kokusai-dori_shop_%E6%B2%96%E7%B9%A9%E8%87%AA%E5%AE%B6%E8%A3%BD%E7%94%9F%E9%BA%B5_Yunami_Sakashita-ten_%E6%9D%BF%E4%B8%8B%E5%BA%97_Restaurant_food_%E8%B1%AC%E8%82%89_Pork_%E6%8E%92%E9%AA%A8%E9%BA%B5_rib_noodle_soup_bowl_February_2026_N13P_02.jpg) | NORTLAUKAU 26088 JP | CC0-1.0 |
| wm-0027 | [Stir-fried ice cream on Buford Highway, September 2016.jpg](https://commons.wikimedia.org/wiki/File:Stir-fried_ice_cream_on_Buford_Highway,_September_2016.jpg) | Thomson200 | CC0-1.0 |
| wm-0028 | [Smoked salmon pasta - Figaros, Brighton 2024-04-19.jpg](https://commons.wikimedia.org/wiki/File:Smoked_salmon_pasta_-_Figaros,_Brighton_2024-04-19.jpg) | Andy Li | CC0-1.0 |
| wm-0029 | [Rythu Vegetables market, Hyderabad 02.jpg](https://commons.wikimedia.org/wiki/File:Rythu_Vegetables_market,_Hyderabad_02.jpg) | Rajasekhar1961 | CC0-1.0 |
| wm-0030 | [HK SKD TKO 坑口 Hang Hau TKO Gateway mall shop breakfast restaurant furniture round table n chairs October 2026 N13P 06.jpg](https://commons.wikimedia.org/wiki/File:HK_SKD_TKO_%E5%9D%91%E5%8F%A3_Hang_Hau_TKO_Gateway_mall_shop_breakfast_restaurant_furniture_round_table_n_chairs_October_2026_N13P_06.jpg) | AGuo WecomU 2007 TAM | CC0-1.0 |
| wm-0031 | [Red Lion Pub Room Interior 2024.jpg](https://commons.wikimedia.org/wiki/File:Red_Lion_Pub_Room_Interior_2024.jpg) | BrooksyTPS | CC0-1.0 |
| wm-0032 | [MC 澳門 Macau Cotai 上蒲京 Grand Lisboa Palace 酒店 hotel room 衣櫃門 November 2024 R12S 02.jpg](https://commons.wikimedia.org/wiki/File:MC_%E6%BE%B3%E9%96%80_Macau_Cotai_%E4%B8%8A%E8%92%B2%E4%BA%AC_Grand_Lisboa_Palace_%E9%85%92%E5%BA%97_hotel_room_%E8%A1%A3%E6%AB%83%E9%96%80_November_2024_R12S_02.jpg) | JohnLEE Brothers | CC0-1.0 |
| wm-0033 | [Bare shelves at Sainsbury's in Woking, 16 March 2020 (4).jpg](https://commons.wikimedia.org/wiki/File:Bare_shelves_at_Sainsbury%27s_in_Woking,_16_March_2020_(4).jpg) | Owen Blacker | CC0-1.0 |
| wm-0034 | [Interior of Metro Espresso Pizza Cafe (Orlando) May 2023.jpg](https://commons.wikimedia.org/wiki/File:Interior_of_Metro_Espresso_Pizza_Cafe_(Orlando)_May_2023.jpg) | Benoît Prieur | CC0-1.0 |
| wm-0035 | [Product shelf in Taquitos Casazul 2023-05-30.jpg](https://commons.wikimedia.org/wiki/File:Product_shelf_in_Taquitos_Casazul_2023-05-30.jpg) | Andy Li | CC0-1.0 |
| wm-0036 | [Office interior 2022 queue.jpg](https://commons.wikimedia.org/wiki/File:Office_interior_2022_queue.jpg) | Rakoon | CC0-1.0 |
| wm-0037 | [MC 澳門 Macau Cotai 上蒲京 Grand Lisboa Palace 酒店 hotel living room November 2024 R12S 68.jpg](https://commons.wikimedia.org/wiki/File:MC_%E6%BE%B3%E9%96%80_Macau_Cotai_%E4%B8%8A%E8%92%B2%E4%BA%AC_Grand_Lisboa_Palace_%E9%85%92%E5%BA%97_hotel_living_room_November_2024_R12S_68.jpg) | JohnLEE Brothers | CC0-1.0 |
| wm-0038 | [BOOKCASE WITH SECRET DOOR, DAR KHALIFA, 2024.jpg](https://commons.wikimedia.org/wiki/File:BOOKCASE_WITH_SECRET_DOOR,_DAR_KHALIFA,_2024.jpg) | Secretum Mundi | CC0-1.0 |
| wm-0039 | [La Junta, Colorado post office interior 4.JPG](https://commons.wikimedia.org/wiki/File:La_Junta,_Colorado_post_office_interior_4.JPG) | Ammodramus | CC0-1.0 |
| wm-0040 | [Premium-Bereich DB Lounge München Hbf 2026-08.jpg](https://commons.wikimedia.org/wiki/File:Premium-Bereich_DB_Lounge_M%C3%BCnchen_Hbf_2026-08.jpg) | Ousw | CC0-1.0 |
| wm-0041 | [Bare shelves at Sainsbury's in Woking, 16 March 2020 (9).jpg](https://commons.wikimedia.org/wiki/File:Bare_shelves_at_Sainsbury%27s_in_Woking,_16_March_2020_(9).jpg) | Owen Blacker | CC0-1.0 |
| wm-0042 | [The Bystander cafe window view towards bus station 2023-08-07.jpg](https://commons.wikimedia.org/wiki/File:The_Bystander_cafe_window_view_towards_bus_station_2023-08-07.jpg) | Andy Li | CC0-1.0 |
| wm-0043 | [Berlin 20261015 Festival of Lights 02.jpg](https://commons.wikimedia.org/wiki/File:Berlin_20261015_Festival_of_Lights_02.jpg) | NutzerAusBerlin | CC0-1.0 |
| wm-0044 | [Tulips in front of the Cathedral of the Deposition of the Holy Robe.jpg](https://commons.wikimedia.org/wiki/File:Tulips_in_front_of_the_Cathedral_of_the_Deposition_of_the_Holy_Robe.jpg) | Vityavo | CC0-1.0 |
| wm-0045 | [Old bridge on the Rio Torretta (2024).jpg](https://commons.wikimedia.org/wiki/File:Old_bridge_on_the_Rio_Torretta_(2024).jpg) | Schwitzenburgenstein | CC0-1.0 |
| wm-0046 | [St. Basil Church, Carrick, tower, 2020-12-10, 01.jpg](https://commons.wikimedia.org/wiki/File:St._Basil_Church,_Carrick,_tower,_2020-12-10,_01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0047 | [2020 08 Bojnice castle 2.jpg](https://commons.wikimedia.org/wiki/File:2020_08_Bojnice_castle_2.jpg) | Qasinka | CC0-1.0 |
| wm-0048 | [ChicagoHarborLighthouseJuly2019.jpg](https://commons.wikimedia.org/wiki/File:ChicagoHarborLighthouseJuly2019.jpg) | JohnDziak | CC0-1.0 |
| wm-0049 | [Fountain in Public Square, Watertown, New York.jpg](https://commons.wikimedia.org/wiki/File:Fountain_in_Public_Square,_Watertown,_New_York.jpg) | Lallint | CC0-1.0 |
| wm-0050 | [Kehra railway bridge 2019.jpg](https://commons.wikimedia.org/wiki/File:Kehra_railway_bridge_2019.jpg) | Zmobbie | CC0-1.0 |
| wm-0051 | [Belle Tout Lighthouse, June 2020 01.jpg](https://commons.wikimedia.org/wiki/File:Belle_Tout_Lighthouse,_June_2020_01.jpg) | Poliphilo | CC0-1.0 |
| wm-0052 | [Bear Lake, August 2024.jpg](https://commons.wikimedia.org/wiki/File:Bear_Lake,_August_2024.jpg) | AutumnNY | CC0-1.0 |
| wm-0053 | [Secret Caverns Waterfall- June 2024.jpg](https://commons.wikimedia.org/wiki/File:Secret_Caverns_Waterfall-_June_2024.jpg) | FossilDS | CC0-1.0 |
| wm-0054 | [2023 Hażlach path to Borgońka.jpg](https://commons.wikimedia.org/wiki/File:2023_Ha%C5%BClach_path_to_Borgo%C5%84ka.jpg) | Qasinka | CC0-1.0 |
| wm-0055 | [2017-01-20 Blick auf Großrinderfeld im Winter - 8.jpg](https://commons.wikimedia.org/wiki/File:2017-01-20_Blick_auf_Gro%C3%9Frinderfeld_im_Winter_-_8.jpg) | Triplec85 | CC0-1.0 |
| wm-0056 | [Autumn colours of leaves at Koishikawa Kourakuen IMG 3863.jpg](https://commons.wikimedia.org/wiki/File:Autumn_colours_of_leaves_at_Koishikawa_Kourakuen_IMG_3863.jpg) | Soseipapa | CC0-1.0 |
| wm-0057 | [Mountain landscape (21827581301).jpg](https://commons.wikimedia.org/wiki/File:Mountain_landscape_(21827581301).jpg) | StockyPics | CC0-1.0 |
| wm-0058 | [Blue trail blaze Anthony's Nose NY.jpg](https://commons.wikimedia.org/wiki/File:Blue_trail_blaze_Anthony%27s_Nose_NY.jpg) | Reconrabbit | CC0-1.0 |
| wm-0059 | [Foxglove on meadow, Eschenhahn.jpg](https://commons.wikimedia.org/wiki/File:Foxglove_on_meadow,_Eschenhahn.jpg) | Gerda Arendt | CC0-1.0 |
| wm-0060 | [2021 Bukowieckie Lake (Skoki).jpg](https://commons.wikimedia.org/wiki/File:2021_Bukowieckie_Lake_(Skoki).jpg) | Qasinka | CC0-1.0 |
| wm-0061 | [Ostia Sea Beach in 2012.01.jpg](https://commons.wikimedia.org/wiki/File:Ostia_Sea_Beach_in_2012.01.jpg) | CAPTAIN RAJU | CC0-1.0 |
| wm-0062 | [Small forest path off Frager Road in Kent, Washington.jpg](https://commons.wikimedia.org/wiki/File:Small_forest_path_off_Frager_Road_in_Kent,_Washington.jpg) | Roc0ast3r | CC0-1.0 |
| wm-0063 | [Autumn leaves came unusally late this year (December 11 2021).jpg](https://commons.wikimedia.org/wiki/File:Autumn_leaves_came_unusally_late_this_year_(December_11_2021).jpg) | Syced | CC0-1.0 |
| wm-0064 | [Mountain Glacier Landscape (from AvoPix).jpg](https://commons.wikimedia.org/wiki/File:Mountain_Glacier_Landscape_(from_AvoPix).jpg) | Unknown @ AvoPix.com | CC0-1.0 |
| wm-0065 | [Guadamía river and beach.jpg](https://commons.wikimedia.org/wiki/File:Guadam%C3%ADa_river_and_beach.jpg) | BBdot | CC0-1.0 |
| wm-0066 | [Meadow with thistles and butterflies, Ennerich.jpg](https://commons.wikimedia.org/wiki/File:Meadow_with_thistles_and_butterflies,_Ennerich.jpg) | Gerda Arendt | CC0-1.0 |
| wm-0067 | [Cascade de la Pissarde.jpg](https://commons.wikimedia.org/wiki/File:Cascade_de_la_Pissarde.jpg) | Wisi eu | CC0-1.0 |
| wm-0068 | [Forest path during autumn.jpg](https://commons.wikimedia.org/wiki/File:Forest_path_during_autumn.jpg) | Paxxen | CC0-1.0 |
| wm-0069 | [Ice on river bank.jpg](https://commons.wikimedia.org/wiki/File:Ice_on_river_bank.jpg) | Terry.grignon | CC0-1.0 |
| wm-0070 | [Cat sleeping AUA (June 2023).JPG](https://commons.wikimedia.org/wiki/File:Cat_sleeping_AUA_(June_2023).JPG) | Benoît Prieur | CC0-1.0 |
| wm-0071 | ['Radhe' the pet cat of Worli fish marke in Mumbai..(Wednesday 14-3-2012).JPG](https://commons.wikimedia.org/wiki/File:%27Radhe%27_the_pet_cat_of_Worli_fish_marke_in_Mumbai..(Wednesday_14-3-2012).JPG) | Rudolph.A.furtado | CC0-1.0 |
| wm-0072 | [Rear view of a dog in the Philippines (9611Photos taken during 2020 coronavirus pandemic 03).jpg](https://commons.wikimedia.org/wiki/File:Rear_view_of_a_dog_in_the_Philippines_(9611Photos_taken_during_2020_coronavirus_pandemic_03).jpg) | Judgefloro | CC0-1.0 |
| wm-0073 | [Sleeping cat in Capri, Italy 2026-05-29.jpg](https://commons.wikimedia.org/wiki/File:Sleeping_cat_in_Capri,_Italy_2026-05-29.jpg) | GuiltyGearFan37 | CC0-1.0 |
| wm-0074 | [Dog Sleeping.jpg](https://commons.wikimedia.org/wiki/File:Dog_Sleeping.jpg) | Ritchde | CC0-1.0 |
| wm-0075 | [Stray cat sleeping on the street of Colombo 2018-03-17.jpg](https://commons.wikimedia.org/wiki/File:Stray_cat_sleeping_on_the_street_of_Colombo_2018-03-17.jpg) | FaysaLBinDaruL | CC0-1.0 |
| wm-0076 | [SZ 深圳 Shenzhen 寶安 BaoAn 萬豐大仟里 MaxLand Mall shop 屋虎貓館 Woo Hoo Pet Cat House February 2025 R12S white.jpg](https://commons.wikimedia.org/wiki/File:SZ_%E6%B7%B1%E5%9C%B3_Shenzhen_%E5%AF%B6%E5%AE%89_BaoAn_%E8%90%AC%E8%B1%90%E5%A4%A7%E4%BB%9F%E9%87%8C_MaxLand_Mall_shop_%E5%B1%8B%E8%99%8E%E8%B2%93%E9%A4%A8_Woo_Hoo_Pet_Cat_House_February_2025_R12S_white.jpg) | LAAePSts Lusnsaz WHA | CC0-1.0 |
| wm-0077 | [Dog on a beach.jpg](https://commons.wikimedia.org/wiki/File:Dog_on_a_beach.jpg) | Unbeatable101 | CC0-1.0 |
| wm-0078 | [Cat matahari sleeping with one eye open.Bizarre..jpg](https://commons.wikimedia.org/wiki/File:Cat_matahari_sleeping_with_one_eye_open.Bizarre..jpg) | Rudolph.A.furtado | CC0-1.0 |
| wm-0079 | [White and gray silverpoint domestic cat lying down in basket.jpg](https://commons.wikimedia.org/wiki/File:White_and_gray_silverpoint_domestic_cat_lying_down_in_basket.jpg) | Poryden | CC0-1.0 |
| wm-0080 | [Dog outside.jpg](https://commons.wikimedia.org/wiki/File:Dog_outside.jpg) | Rruunnaa | CC0-1.0 |
| wm-0081 | [Cat - Moomin.jpg](https://commons.wikimedia.org/wiki/File:Cat_-_Moomin.jpg) | Tetizeraz | CC0-1.0 |
| wm-0082 | [Cat chews on bottle.jpg](https://commons.wikimedia.org/wiki/File:Cat_chews_on_bottle.jpg) | Punker1999 | CC0-1.0 |
| wm-0083 | [Pūriri unripe fruit 20250702 130645.jpg](https://commons.wikimedia.org/wiki/File:P%C5%ABriri_unripe_fruit_20250702_130645.jpg) | Prosperosity | CC0-1.0 |
| wm-0084 | [Pūriri flower 20250702 130801.jpg](https://commons.wikimedia.org/wiki/File:P%C5%ABriri_flower_20250702_130801.jpg) | Prosperosity | CC0-1.0 |
| wm-0085 | [Carex flagellifera 'Toffee Twist' - Lyman Plant House, Smith College - DSC04215.JPG](https://commons.wikimedia.org/wiki/File:Carex_flagellifera_%27Toffee_Twist%27_-_Lyman_Plant_House,_Smith_College_-_DSC04215.JPG) | Daderot | CC0-1.0 |
| wm-0086 | [Portland International Rose Test Garden - HCP - October 15, 2022 - 008.jpg](https://commons.wikimedia.org/wiki/File:Portland_International_Rose_Test_Garden_-_HCP_-_October_15,_2022_-_008.jpg) | Vulturesong | CC0-1.0 |
| wm-0087 | [Washingtonia x filibusta small 01.jpg](https://commons.wikimedia.org/wiki/File:Washingtonia_x_filibusta_small_01.jpg) | B137 | CC0-1.0 |
| wm-0088 | [Iowa Tulip.jpg](https://commons.wikimedia.org/wiki/File:Iowa_Tulip.jpg) | Maatpublishing | CC0-1.0 |
| wm-0089 | [Portland International Rose Test Garden - HCP - October 15, 2022 - 009.jpg](https://commons.wikimedia.org/wiki/File:Portland_International_Rose_Test_Garden_-_HCP_-_October_15,_2022_-_009.jpg) | Vulturesong | CC0-1.0 |
| wm-0090 | [Beavertail Cactus Flower Crazy (2547547776).jpg](https://commons.wikimedia.org/wiki/File:Beavertail_Cactus_Flower_Crazy_(2547547776).jpg) | cogdogblog | CC0-1.0 |
| wm-0091 | [Aglaonema simplex - Lyman Plant House, Smith College - DSC04243.JPG](https://commons.wikimedia.org/wiki/File:Aglaonema_simplex_-_Lyman_Plant_House,_Smith_College_-_DSC04243.JPG) | Daderot | CC0-1.0 |
| wm-0092 | [Portland International Rose Test Garden - HCP - October 15, 2022 - 013.jpg](https://commons.wikimedia.org/wiki/File:Portland_International_Rose_Test_Garden_-_HCP_-_October_15,_2022_-_013.jpg) | Vulturesong | CC0-1.0 |
| wm-0093 | [観葉植物.jpg](https://commons.wikimedia.org/wiki/File:%E8%A6%B3%E8%91%89%E6%A4%8D%E7%89%A9.jpg) | 椿七十郎 | CC0-1.0 |
| wm-0094 | [Ostia Sea Beach in 2012.04.jpg](https://commons.wikimedia.org/wiki/File:Ostia_Sea_Beach_in_2012.04.jpg) | CAPTAIN RAJU | CC0-1.0 |
| wm-0095 | [Aruba — Catamaran Sailing at Sunset — 2023.jpg](https://commons.wikimedia.org/wiki/File:Aruba_%E2%80%94_Catamaran_Sailing_at_Sunset_%E2%80%94_2023.jpg) | Rarends297 | CC0-1.0 |
| wm-0096 | [2024-09-17 near-equinoctial sunrise in Chicago, Illinois viewed along Jackson Boulevard 02.jpg](https://commons.wikimedia.org/wiki/File:2024-09-17_near-equinoctial_sunrise_in_Chicago,_Illinois_viewed_along_Jackson_Boulevard_02.jpg) | Dan Leonard | CC0-1.0 |
| wm-0097 | [IMG Clouds sky.jpg](https://commons.wikimedia.org/wiki/File:IMG_Clouds_sky.jpg) | Liyan Alsaideh14 | CC0-1.0 |
| wm-0098 | [Streetcar and rainbow, Beechview, 2023-01-25, 01.jpg](https://commons.wikimedia.org/wiki/File:Streetcar_and_rainbow,_Beechview,_2023-01-25,_01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0099 | [20200309 Night sky.jpg](https://commons.wikimedia.org/wiki/File:20200309_Night_sky.jpg) | Gb89.2 | CC0-1.0 |
| wm-0100 | [Sunset over Beechview, 2021-09-25, 01.jpg](https://commons.wikimedia.org/wiki/File:Sunset_over_Beechview,_2021-09-25,_01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0101 | [Evening sky 2024.jpg](https://commons.wikimedia.org/wiki/File:Evening_sky_2024.jpg) | Swathi sri srinivasa raghavan | CC0-1.0 |
| wm-0102 | [Waxing half moon over Brofjorden 2.jpg](https://commons.wikimedia.org/wiki/File:Waxing_half_moon_over_Brofjorden_2.jpg) | W.carter | CC0-1.0 |
| wm-0103 | [Sunset clouds over Beechview,2022-12ť8,01.jpg](https://commons.wikimedia.org/wiki/File:Sunset_clouds_over_Beechview,2022-12%C5%A58,01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0104 | [Moon-sky night.jpg](https://commons.wikimedia.org/wiki/File:Moon-sky_night.jpg) | ChahadiQw | CC0-1.0 |
| wm-0105 | [Sunset bright, sep 11 2026.jpg](https://commons.wikimedia.org/wiki/File:Sunset_bright,_sep_11_2026.jpg) | Logan M Diel | CC0-1.0 |
| wm-0106 | [Ole Miss vs Penn State, 2023 Peach Bowl, Mercedes-Benz Stadium, Atlanta.jpg](https://commons.wikimedia.org/wiki/File:Ole_Miss_vs_Penn_State,_2023_Peach_Bowl,_Mercedes-Benz_Stadium,_Atlanta.jpg) | Marycollinsc | CC0-1.0 |
| wm-0107 | [Basketball Court-2024.jpg](https://commons.wikimedia.org/wiki/File:Basketball_Court-2024.jpg) | Louis lnak1410 | CC0-1.0 |
| wm-0108 | [Epsom Tennis Club (July 2021).jpg](https://commons.wikimedia.org/wiki/File:Epsom_Tennis_Club_(July_2021).jpg) | Mertbiol | CC0-1.0 |
| wm-0109 | [Toyokawa City Athletic Field (2017-05-28) 2.jpg](https://commons.wikimedia.org/wiki/File:Toyokawa_City_Athletic_Field_(2017-05-28)_2.jpg) | Lombroso | CC0-1.0 |
| wm-0110 | [Ball State Cardinals at Northwestern Wildcats football view from north endzone main concourse (2026-10-10).jpg](https://commons.wikimedia.org/wiki/File:Ball_State_Cardinals_at_Northwestern_Wildcats_football_view_from_north_endzone_main_concourse_(2026-10-10).jpg) | Candycaneman | CC0-1.0 |
| wm-0111 | [DJ Sherrington Park skate bowl Blunder Rd and Inala Ave Inala P1380679.jpg](https://commons.wikimedia.org/wiki/File:DJ_Sherrington_Park_skate_bowl_Blunder_Rd_and_Inala_Ave_Inala_P1380679.jpg) | John Robert McPherson | CC0-1.0 |
| wm-0112 | [Basketball court, Mid Street Recreation Ground, Nutfield, Surrey - May 2026 - 02.jpg](https://commons.wikimedia.org/wiki/File:Basketball_court,_Mid_Street_Recreation_Ground,_Nutfield,_Surrey_-_May_2026_-_02.jpg) | Mertbiol | CC0-1.0 |
| wm-0113 | [Dyke Road Park Tennis Courts 2023-06-03.jpg](https://commons.wikimedia.org/wiki/File:Dyke_Road_Park_Tennis_Courts_2023-06-03.jpg) | Andy Li | CC0-1.0 |
| wm-0114 | [Market in Zagreb.jpg](https://commons.wikimedia.org/wiki/File:Market_in_Zagreb.jpg) | HHRIA123 | CC0-1.0 |
| wm-0115 | [20200925-dutch-alley-1930s.jpg](https://commons.wikimedia.org/wiki/File:20200925-dutch-alley-1930s.jpg) | Jeroen Hoek | CC0-1.0 |
| wm-0116 | [No parking sign Khorenatsi street, Yerevan (May 2018).jpg](https://commons.wikimedia.org/wiki/File:No_parking_sign_Khorenatsi_street,_Yerevan_(May_2018).jpg) | Benoît Prieur | CC0-1.0 |
| wm-0117 | [Traffic light sign 20240322 130206.jpg](https://commons.wikimedia.org/wiki/File:Traffic_light_sign_20240322_130206.jpg) | Taufik | CC0-1.0 |
| wm-0118 | [CARTA bus stop - October 2025 - Sarah Stierch.jpg](https://commons.wikimedia.org/wiki/File:CARTA_bus_stop_-_October_2025_-_Sarah_Stierch.jpg) | Missvain | CC0-1.0 |
| wm-0119 | [Disabled pedestrian crossing sign 20250615 161240.jpg](https://commons.wikimedia.org/wiki/File:Disabled_pedestrian_crossing_sign_20250615_161240.jpg) | Taufik | CC0-1.0 |
| wm-0120 | [Alley of trees decorated with Christmas lights (2022-12-31) 2.jpg](https://commons.wikimedia.org/wiki/File:Alley_of_trees_decorated_with_Christmas_lights_(2022-12-31)_2.jpg) | Almanta | CC0-1.0 |
| wm-0121 | [שלטי חניה בתשלום ברחוב רוגוזין, רובע ד' באשדוד, ינואר 2025.jpg](https://commons.wikimedia.org/wiki/File:%D7%A9%D7%9C%D7%98%D7%99_%D7%97%D7%A0%D7%99%D7%94_%D7%91%D7%AA%D7%A9%D7%9C%D7%95%D7%9D_%D7%91%D7%A8%D7%97%D7%95%D7%91_%D7%A8%D7%95%D7%92%D7%95%D7%96%D7%99%D7%9F,_%D7%A8%D7%95%D7%91%D7%A2_%D7%93%27_%D7%91%D7%90%D7%A9%D7%93%D7%95%D7%93,_%D7%99%D7%A0%D7%95%D7%90%D7%A8_2025.jpg) | מקף־עברי | CC0-1.0 |
| wm-0122 | [Crossing marked with a traffic sign 20190517 184744 HDR.jpg](https://commons.wikimedia.org/wiki/File:Crossing_marked_with_a_traffic_sign_20190517_184744_HDR.jpg) | Mateusz Konieczny | CC0-1.0 |
| wm-0123 | [20200806 164500 things places in south korea IMG 9609.jpg](https://commons.wikimedia.org/wiki/File:20200806_164500_things_places_in_south_korea_IMG_9609.jpg) | Choi Kwang-mo | CC0-1.0 |
| wm-0124 | [Bus stop at Samad Vurgun.jpg](https://commons.wikimedia.org/wiki/File:Bus_stop_at_Samad_Vurgun.jpg) | rwp | CC0-1.0 |
| wm-0125 | [Refurbished Musselburgh Rise pedestrian crossing, 29 Jul 2026.jpg](https://commons.wikimedia.org/wiki/File:Refurbished_Musselburgh_Rise_pedestrian_crossing,_29_Jul_2026.jpg) | Andykatib | CC0-1.0 |
| wm-0126 | [Berlin Reinickendorf frog graffiti on house wall 20260819 02.jpg](https://commons.wikimedia.org/wiki/File:Berlin_Reinickendorf_frog_graffiti_on_house_wall_20260819_02.jpg) | NutzerAusBerlin | CC0-1.0 |
| wm-0127 | [No parking sign cutcot pulilan 20241205jwilz.jpg](https://commons.wikimedia.org/wiki/File:No_parking_sign_cutcot_pulilan_20241205jwilz.jpg) | JWilz12345 | CC0-1.0 |
| wm-0128 | [Bücherschrank Baldham Marktplatz 2025-03-24.jpg](https://commons.wikimedia.org/wiki/File:B%C3%BCcherschrank_Baldham_Marktplatz_2025-03-24.jpg) | Felix Edelmann | CC0-1.0 |
| wm-0129 | [SZ 深圳 Shenzhen 龍華 Longhua 旺民路 Wangmin Road park yellow public sharing bicycle parking February 2025 R12S 02.jpg](https://commons.wikimedia.org/wiki/File:SZ_%E6%B7%B1%E5%9C%B3_Shenzhen_%E9%BE%8D%E8%8F%AF_Longhua_%E6%97%BA%E6%B0%91%E8%B7%AF_Wangmin_Road_park_yellow_public_sharing_bicycle_parking_February_2025_R12S_02.jpg) | ALB 302 AOE woapsing | CC0-1.0 |
| wm-0130 | [Street views in Hitech City (55904).jpg](https://commons.wikimedia.org/wiki/File:Street_views_in_Hitech_City_(55904).jpg) | Syced | CC0-1.0 |
| wm-0131 | [Bicycles Mannerheim Park Oulu 20210209.jpg](https://commons.wikimedia.org/wiki/File:Bicycles_Mannerheim_Park_Oulu_20210209.jpg) | Estormiz | CC0-1.0 |
| wm-0132 | [Moscow, Mira Prospect, bikes May 2025 04.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_Mira_Prospect,_bikes_May_2025_04.jpg) | Retired electrician | CC0-1.0 |
| wm-0133 | [Darnall station car park, June 2021.jpg](https://commons.wikimedia.org/wiki/File:Darnall_station_car_park,_June_2021.jpg) | TheFrog001 | CC0-1.0 |
| wm-0134 | [Kuzuryuko Station platform 20120909.jpg](https://commons.wikimedia.org/wiki/File:Kuzuryuko_Station_platform_20120909.jpg) | Fumon1987a | CC0-1.0 |
| wm-0135 | [Moscow, small motorcycle, May 2026 01.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_small_motorcycle,_May_2026_01.jpg) | Retired electrician | CC0-1.0 |
| wm-0136 | [Moscow, Kaluzhskaya Ploshchad tram loop June 2022 07.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_Kaluzhskaya_Ploshchad_tram_loop_June_2022_07.jpg) | Retired electrician | CC0-1.0 |
| wm-0137 | [Moscow, Velobike electro-scooter, July 2025 03.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_Velobike_electro-scooter,_July_2025_03.jpg) | Retired electrician | CC0-1.0 |
| wm-0138 | [Ouluhalli Car Park 20250216.jpg](https://commons.wikimedia.org/wiki/File:Ouluhalli_Car_Park_20250216.jpg) | Estormiz | CC0-1.0 |
| wm-0139 | [Moscow, BMW motorcycle red, June 2026 01.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_BMW_motorcycle_red,_June_2026_01.jpg) | Retired electrician | CC0-1.0 |
| wm-0140 | [York Inset Scooter Club Show and Shine 2025 02.jpg](https://commons.wikimedia.org/wiki/File:York_Inset_Scooter_Club_Show_and_Shine_2025_02.jpg) | Malcolmxl5 | CC0-1.0 |
