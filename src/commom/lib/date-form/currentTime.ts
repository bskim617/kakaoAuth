export const getCurrentDate = (value, date = new Date()) => {
  const year = date.getFullYear();
  const month = date.getMonth();
  const today = date.getDate();
  const hours = date.getHours();
  const minutes = date.getMinutes();
  const seconds = date.getSeconds();
  const milliseconds = date.getMilliseconds();

  if (value === 'today') {
    return new Date(Date.UTC(year, month, today));
  } else if (value === 'month') {
    return new Date(Date.UTC(year, month));
  } else {
    return new Date(
      Date.UTC(year, month, today, hours, minutes, seconds, milliseconds),
    );
  }
};

export const birthdayFormat = (date: Date) => {
  const year = date.getFullYear();
  const month = date.getMonth();
  const today = date.getDate();

  return new Date(Date.UTC(year, month, today));
};
