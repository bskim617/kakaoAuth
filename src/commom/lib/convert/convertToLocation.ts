const convertToLocation = (address) => {
  let [city, gu, ...rest] = address.split(' ');
  if (city === '제주특별자치도') {
    city = '제주';
  }

  let detail = '';
  rest.forEach((word, index) => {
    if (index === rest.length - 1) detail += word;
    else detail += word + ' ';
  });
  return { city, gu, detail };
};

export default convertToLocation;
